### 一、项目简介

#### 1、为什么写这个？

闲的没事干（真的）

#### 2、更新吗？

不想更（大部分都是AI写的）

### 二、项目依赖

- Go  1.22
- MySQL  5.7.44

### 三、启动

运行

```shell
go run main.go
```

编译

```shell
go build main.go -o auth
```

> 项目第一次启动会生成一个config.json
> 需要自行配置MySQL数据库连接地址
> 第二次运行会自动生成所需要数据表


### 四、文档

[API狐狸](https://guguauth.apifox.cn/)

> 数据库中key是MySQL关键字，后期改了下，但是文档懒得改了，见谅
