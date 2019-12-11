# keycloak-services-social-dingtalk
Keycloak社会化登录-钉钉扫码登录-插件

构建: mvn clean package

安装步骤:

* 安装jar包到Keycloak server (providers文件夹如果没有，请先新建文件夹):
  * `$ cp target/keycloak-services-social-dingtalk-{x.y.z}.jar _KEYCLOAK_HOME_/providers/`
  
* 添加配置页面到Keycloak server:
  * `$ cp themes/base/admin/resources/partials/realm-identity-provider-dingtalk.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials/`
  * `$ cp themes/base/admin/resources/partials/realm-identity-provider-dingtalk-ext.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials/`

* 修改module.xml
 * `$ cd modules/system/layers/keycloak/org/keycloak/keycloak-services/main/`
 修改module.xml,在<dependencies>节点中新增
 ```html
 <dependencies>
        <module name="org.infinispan" services="import"/>
        ...
  </dependencies>
 ```

启动以后需要填写钉钉扫码登录的key和secret

based on https://github.com/jyqq163/keycloak-services-social-weixin
