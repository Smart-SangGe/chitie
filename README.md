# chitie 赤铁

更快的[Linpeas](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)rust实现。

在我们渗透测试提权过程中，常常用到Linpeas脚本，但是扫描速度是在是太慢了！

> By default linpeas takes around 4 mins to complete, but It could take from 5 to 10 minutes to execute all the checks using -a parameter (Recommended option for CTFs)

## 目标

1. 速度有大幅度提升
2. 保持输出易于阅读
3. 实现原项目较残缺的报告导出功能
4. 小体积
5. 单文件部署，静态编译不依赖任何外部库

## 架构设计

### 核心设计原则

1. **模块化** - 每个检查类别是独立模块，便于维护和扩展
2. **并发执行** - 使用Rust异步运行时并行执行独立检查，提升速度
3. **零依赖系统命令** - 直接读取 `/proc`、`/sys`、`/etc` 等，尽可能不调用外部命令
4. **统一结果格式** - 所有检查返回标准化的Finding结构，便于报告生成

### 目录结构

```
chitie/
├── src/
│   ├── main.rs                 # CLI入口，参数解析
│   ├── lib.rs                  # 库入口
│   ├── cli.rs                  # 命令行参数定义（兼容LinPEAS）
│   ├── config.rs               # 运行配置（-a/-e/-r/-s等）
│   ├── runner.rs               # 检查执行器（并发调度）
│   ├── findings.rs             # Finding/Severity/Category数据结构
│   ├── output/                 # 输出模块
│   │   ├── mod.rs
│   │   ├── terminal.rs         # 彩色终端输出
│   │   ├── json.rs             # JSON导出
│   │   ├── xml.rs              # XML导出
│   │   └── html.rs             # HTML报告
│   ├── checks/                 # 检查模块（对应LinPEAS分类）
│   │   ├── mod.rs
│   │   ├── system.rs           # 系统信息（OS、内核、架构）
│   │   ├── container.rs        # 容器检测（Docker、K8s等）
│   │   ├── cloud.rs            # 云环境检测（AWS、Azure、GCP）
│   │   ├── processes.rs        # 进程、Cron、定时器、服务
│   │   ├── network.rs          # 网络接口、端口、防火墙
│   │   ├── users.rs            # 用户、组、sudo权限
│   │   ├── software.rs         # 已安装软件、版本
│   │   ├── permissions.rs      # SUID/SGID/Capabilities
│   │   ├── files.rs            # 敏感文件、配置文件
│   │   └── secrets.rs          # API密钥、密码正则搜索
│   └── utils/                  # 工具函数
│       ├── mod.rs
│       ├── fs.rs               # 文件系统操作
│       ├── proc.rs             # /proc解析
│       ├── sys.rs              # /sys解析
│       ├── parsers.rs          # 配置文件解析器
│       └── vulns.rs            # 漏洞数据库（内核版本映射）
└── Cargo.toml
```

### 数据流

```
CLI参数 → Config → Runner → 并发执行各模块 → Finding[] → Output格式化 → 终端/文件
```

### 关键技术选型

- **异步运行时**: tokio（多线程并发执行检查）
- **CLI**: clap（参数解析）
- **序列化**: serde（JSON/XML导出）
- **文件遍历**: walkdir（查找SUID等）
- **正则**: regex（密钥搜索）
- **彩色输出**: colored（终端高亮）
- **静态链接**: musl（零依赖部署）

## 性能对比
