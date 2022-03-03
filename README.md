# Spring_CVE_2022_22947
Spring_CVE_2022_22947:Spring Cloud Gateway现高风险漏洞cve,poc漏洞利用,一键利用,开箱即用
#  漏洞描述 ：
### Spring Cloud Gateway是Spring中的一个API网关。其3.1.0及3.0.6版本（包含）以前存在一处SpEL表达式注入漏洞，当攻击者可以访问Actuator API的情况下，将可以利用该漏洞执行任意命令。 
# 影  :    响范围 :
## Spring Cloud Gateway以下版本均受影响：

    3.1.0
    3.0.0至3.0.6
    其他老版本 
    
#  缓解方法 ： 
    3.1.x用户应升级到3.1.1+
    3.0.x用户应升级到3.0.7+
    如果不需要Actuator端点，可以通过management.endpoint.gateway.enable：false配置将其禁用
    如果需要Actuator端点，则应使用Spring Security对其进行保护 

CVE-2022-22946：HTTP2 不安全的 TrustManager :

严重性 ： Medium 


# ::p oc :


正在编译中

