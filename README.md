# Webshell Monitor

## 功能

- [ ] 推送webshell存活状态变更
  - [X] 钉钉
  - [ ] 飞书
- [X] 通过命令行添加要监控的webshell
- [X] 交互式添加要监控的webshell
- [ ] 批量添加要监控的webshell
- [ ] 使用webhook参数启动

## 使用

```text
$ python3 monitor.py -h


 _____________________
< Oh!webshell Online! >
 ---------------------
        \   ^__^
         \  (oo)\_______      @Author: Arm!tage
            (__)\       )\/\  @Version: v0.2.0_alpha
                ||----w |
                ||     ||

USAGE:
    Run Service
        python3 monitor.py server

    Use Client
        python3 monitor.py list
        python3 monitor.py add [<name> <path> <description>]
        python3 monitor.py del [uuid]
        pyhton3 monitor.py load <config file>
        python3 monitor.py delay <seconds>

    Export
        curl -k http://127.0.0.1:14500/list
```
