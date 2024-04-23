# Webshell Monitor

## 功能

- [x] 钉钉推送webshell存活状态变更
- [x] 通过命令行添加要监控的webshell
- [x] 交互式添加要监控的webshell
- [ ] 批量添加要监控的webshell

## 使用

```text
$ python3 monitor.py -h

USAGE:
    Run Service
        python3 monitor.py server

    Use Client
        python3 monitor.py list
        python3 monitor.py add [<name> <path> <description>]
        python3 monitor.py del [uuid]
        pyhton3 monitor.py load <config file>

    Export
        curl -k http://127.0.0.1:14500/list
```
