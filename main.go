package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// 配置文件结构
type Config struct {
	DBUser     string `json:"db_user"`
	DBPassword string `json:"db_password"`
	DBHost     string `json:"db_host"`
	DBPort     string `json:"db_port"`
	DBName     string `json:"db_name"`
}

// 数据库模型定义（修复关键字冲突）
type AuthKey struct { // 重命名结构体，避免使用Key关键字
	AuthKey string `gorm:"primaryKey;column:auth_key" json:"key"` // 列名改为auth_key，避免冲突
	Time    int    `json:"time"`  // -1永久、30一个月、365一年
	State   int    `json:"state"` // 0未使用、1已使用
}

// 自定义表名，避免与MySQL关键字冲突
func (AuthKey) TableName() string {
	return "auth_keys"
}

type Auth struct {
	AuthKey string `gorm:"primaryKey;column:auth_key" json:"key"` // 关联的授权码
	Domain  string `json:"domain"`
	Time    int    `json:"time"`
	State   int    `json:"state"`
	Cert    string `json:"cert"`   // Base64编码的证书
	Token   string `json:"token"`
	Hash    string `json:"hash"`
}

type Cert struct {
	Domain  string `gorm:"primaryKey" json:"domain"`
	Cert    string `json:"cert"`    // Base64编码的证书
	Private string `json:"private"` // Base64编码的私钥
	Token   string `json:"token"`
	Hash    string `json:"hash"`
}

var db *gorm.DB
var config Config

func main() {
	// 检查并加载配置文件
	loadConfig()

	// 初始化数据库连接
	initDB()

	// 初始化路由
	r := gin.Default()

	// 前端接口
	r.GET("/Inquire", inquireHandler)
	r.GET("/bind", bindHandler)

	// 用户接口
	r.GET("/verify", verifyHandler)

	// 管理员接口
	r.GET("/admin/addkey", addKeyHandler)
	r.GET("/admin/delkey", delKeyHandler)

	// 启动服务
	r.Run(":8080")
}

// 加载配置文件，首次运行生成默认配置
func loadConfig() {
	configPath := "config.json"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// 生成默认配置文件
		defaultConfig := Config{
			DBUser:     "root",
			DBPassword: "password",
			DBHost:     "127.0.0.1",
			DBPort:     "3306",
			DBName:     "guguauth",
		}
		data, err := json.MarshalIndent(defaultConfig, "", "  ")
		if err != nil {
			panic("生成配置文件失败: " + err.Error())
		}
		if err := os.WriteFile(configPath, data, 0644); err != nil {
			panic("写入配置文件失败: " + err.Error())
		}
		fmt.Println("已生成默认配置文件 config.json，请根据实际环境修改后重新运行程序")
		os.Exit(0)
	}

	// 读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		panic("读取配置文件失败: " + err.Error())
	}
	if err := json.Unmarshal(data, &config); err != nil {
		panic("解析配置文件失败: " + err.Error())
	}
}

// 初始化数据库连接并自动迁移数据表
func initDB() {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		config.DBUser,
		config.DBPassword,
		config.DBHost,
		config.DBPort,
		config.DBName,
	)
	var err error
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("数据库连接失败: " + err.Error())
	}

	// 自动迁移数据表（第二次运行时会创建表）
	err = db.AutoMigrate(&AuthKey{}, &Auth{}, &Cert{})
	if err != nil {
		panic("数据表迁移失败: " + err.Error())
	}
	fmt.Println("数据库连接成功，数据表已初始化")
}

// 授权查询接口 /Inquire
func inquireHandler(c *gin.Context) {
	domain := c.Query("domain")
	if domain == "" {
		c.JSON(http.StatusOK, gin.H{"status": false})
		return
	}

	var auth Auth
	result := db.Where("domain = ?", domain).First(&auth)
	if result.Error != nil {
		c.JSON(http.StatusOK, gin.H{"status": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": true})
}

// 授权绑定接口 /bind
func bindHandler(c *gin.Context) {
	domain := c.Query("domain")
	key := c.Query("key")
	if domain == "" || key == "" {
		c.JSON(http.StatusOK, gin.H{"error": "参数缺失"})
		return
	}

	// 验证key是否有效
	var keyInfo AuthKey
	result := db.Where("auth_key = ? AND state = 0", key).First(&keyInfo)
	if result.Error != nil {
		c.JSON(http.StatusOK, gin.H{"error": "无效的key"})
		return
	}

	// 生成证书和私钥
	certPEM, privatePEM, err := generateCertificate(domain)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": "证书生成失败: " + err.Error()})
		return
	}

	// 生成32位Token
	token := generateToken(32)

	// Base64编码证书和私钥
	certBase64 := base64.StdEncoding.EncodeToString([]byte(certPEM))
	privateBase64 := base64.StdEncoding.EncodeToString([]byte(privatePEM))

	// 计算哈希值 (certBase64 + token)
	hash := calculateHash(certBase64 + token)

	// 更新key状态为已使用
	db.Model(&AuthKey{}).Where("auth_key = ?", key).Update("state", 1)

	// 写入auth表
	auth := Auth{
		AuthKey: key,
		Domain:  domain,
		Time:    keyInfo.Time,
		State:   1,
		Cert:    certBase64,
		Token:   token,
		Hash:    hash,
	}
	db.Create(&auth)

	// 写入cert表
	cert := Cert{
		Domain:  domain,
		Cert:    certBase64,
		Private: privateBase64,
		Token:   token,
		Hash:    hash,
	}
	db.Create(&cert)

	c.JSON(http.StatusOK, gin.H{
		"cert":    certBase64,
		"private": privateBase64,
		"token":   token,
		"hash":    hash,
	})
}

// 授权验证接口 /verify
func verifyHandler(c *gin.Context) {
	domain := c.Query("domain")
	cert := c.Query("cert")
	hash := c.Query("hash")

	if domain == "" || cert == "" || hash == "" {
		c.JSON(http.StatusOK, gin.H{"status": false})
		return
	}

	var certInfo Cert
	result := db.Where("domain = ?", domain).First(&certInfo)
	if result.Error != nil {
		c.JSON(http.StatusOK, gin.H{"status": false})
		return
	}

	// 验证证书和哈希是否匹配
	if certInfo.Cert == cert && certInfo.Hash == hash {
		c.JSON(http.StatusOK, gin.H{"status": true})
	} else {
		c.JSON(http.StatusOK, gin.H{"status": false})
	}
}

// 添加Key接口 /admin/addkey
func addKeyHandler(c *gin.Context) {
	numberStr := c.Query("number")
	if numberStr == "" {
		c.JSON(http.StatusOK, gin.H{"error": "请指定数量"})
		return
	}

	number, err := strconv.Atoi(numberStr)
	if err != nil || number <= 0 {
		c.JSON(http.StatusOK, gin.H{"error": "无效的数量"})
		return
	}

	keys := make(map[string]string)
	for i := 0; i < number; i++ {
		key := generateToken(16) // 生成16位key
		keyName := fmt.Sprintf("key%d", i+1)
		keys[keyName] = key
		db.Create(&AuthKey{
			AuthKey: key,
			Time:    -1, // 默认永久
			State:   0,  // 未使用
		})
	}

	c.JSON(http.StatusOK, gin.H{"keys": keys})
}

// 删除Key接口 /admin/delkey
func delKeyHandler(c *gin.Context) {
	key := c.Query("key")
	if key == "" {
		c.JSON(http.StatusOK, gin.H{"status": false})
		return
	}

	// 删除key表中的记录
	db.Delete(&AuthKey{}, "auth_key = ?", key)

	// 更新auth表中相关记录状态
	db.Model(&Auth{}).Where("auth_key = ?", key).Update("state", 0)

	c.JSON(http.StatusOK, gin.H{"status": true})
}

// 生成自签证书
func generateCertificate(domain string) (certPEM, privatePEM string, err error) {
	// 生成RSA私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// 准备证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"咕咕授权站"},
			Locality:     []string{"Changchun"},
			Province:     []string{"Jilin"},
			Country:      []string{"CN"},
		},
		Issuer: pkix.Name{
			CommonName:   "Guguauth",
			Organization: []string{"Guguauth"},
			Country:      []string{"CN"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0), // 5年有效期
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 生成证书
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", err
	}

	// 编码证书为PEM格式
	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	certPEM = string(pem.EncodeToMemory(certBlock))

	// 编码私钥为PEM格式
	privateBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	privatePEM = string(pem.EncodeToMemory(privateBlock))

	return certPEM, privatePEM, nil
}

// 生成指定长度的随机Token（大小写字母+数字）
func generateToken(length int) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

// 计算哈希值（SHA256）
func calculateHash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}