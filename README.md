# xia SQL (瞎注)

> 本插件仅只插入单引号，没有其他盲注啥的，且返回的结果需要人工介入去判断是否存在注入，如果需要所有注入都测试，请把burp的流量转发到xray。

* burp 插件。
* 在每个参数后面填加一个单引号，两个单引号,如果值为纯数字则多加一个-1、-0。
* 由于不会java，且又是用java写的，代码太烂，勿喷。`
* 感谢名单：Moonlit、阿猫阿狗、Shincehor、Xm17

***********

## 插件使用描述
* 返回 `✔️` 代表两个单引号的长度和一个单引号的长度不一致，`表明可能存在注入`。
* 返回 `✔️ ==> ？` 代表着 原始包的长度和两个单引号的长度相同且和一个单引号的长度不同，`表明很可能是注入`。
* 返回 `diy payload` 代表自定义的payload。
* 返回 `time > 3` 代表访问网站的时间大于3秒，可利用该功能配合自定义payload功能测试`时间盲注`。
* 支持json格式，V1.9以上版本`已支持json多层嵌套`。
* 支持参数的值是`纯数字则-1，-0`。
* 支持cookie测试
* 支持`右键发送到插件扫描`（哪怕之前扫描过的，仍然可以通过右键发送再次扫描）备注：右键发送一定需要有响应包，不然发不过去，这样才能对比和原数据包的长度。
* 支持`自定义payload`。
* 支持自定义payload中的参数值`置空`。
* 监控Proxy流量。
* 监控Repeater流量。
* 同个数据包只扫描一次，算法：`MD5(不带参数的url+参数名+POST/GET)`。


**********
### 2022-5-27
#### xia SQL 2.4
* 新增支持对cookie测试

![image](https://user-images.githubusercontent.com/30351807/170674995-f5595cc4-afe6-4d74-97d3-6175c4966519.png)


**********
### 2022-5-24
#### xia SQL 2.3
* 新增 状态一列，`run……` 表示正在发送相关payload，`end!` 表示已经扫描完成，`end! ✔️`表示扫描完成且结果可能存在注入。

![image](https://user-images.githubusercontent.com/30351807/169846432-106a0764-7f20-466e-831d-8b8615c9dda7.png)


**********
### 2022-5-20
#### xia SQL 2.2
* 优化proxy模式有时流量不过来问题。
* 优化Proxy、Repeater 模式下，静态资源不处理。后缀：jpg、png、gif、css、js、pdf、mp3、mp4、avi`(右键发送不影响)`

![image](https://user-images.githubusercontent.com/30351807/169476496-e2a7351b-f701-42f8-b56b-a8d411ab6eca.png)


**********
### 2022-5-12
#### xia SQL 2.1
* 新增 自定义payload中参数值置空

![image](https://user-images.githubusercontent.com/30351807/168087873-1e57c10d-cf66-4783-af1e-3d075f629c4d.png)

**********
### 2022-4-25
#### xia SQL 2.0
* ui界面优化
* 添加自定义payload功能
* 自定义payload访问网站时间大于3秒，将显示 time > 3。

![image](https://user-images.githubusercontent.com/30351807/165055862-c0a3a72e-918c-47b7-84ad-f74b1cb2f365.png)

![image](https://user-images.githubusercontent.com/30351807/165055655-1ac9b40a-4c68-424a-b73e-f31b3b5f1162.png)

**********
### 2022-4-11
#### xia SQL 1.9
* 支持json多层嵌套
* 新增列：用时，用于后期更新自定义payload时，可以查看到每个数据包所用的时间。
![image](https://user-images.githubusercontent.com/30351807/162653146-5caaf300-3b1c-4680-af06-e84364a5e3b4.png)


**********
### 2022-4-8
#### xia SQL 1.8
* 新增右键发送到插件扫描
* 优化 监控Repeater 模式下数据包返回速度。
![image](https://user-images.githubusercontent.com/30351807/162444663-ecc491e2-9a74-4d0f-8b1f-c6ce8f61546a.png)


**********
### 2022-4-2
#### xia SQL 1.7
* 修复在burp2.x版本下poxry模式展示内容bug
![image](https://user-images.githubusercontent.com/30351807/161375553-cee2df69-5681-4818-95ae-0ed389795ea4.png)


**********
### 2022-3-31
#### xia SQL 1.6
* 更新相同数据包只扫描一次的算法，算法：MD5(不带参数的url+参数名+POST/GET)
![image](https://user-images.githubusercontent.com/30351807/161045937-d0e3584a-d610-4b26-ba33-6cc08dd9e8fa.png)


**********
### 2022-3-29
#### xia SQL 1.5
* 取消默认选中“监控Repeater”，增加默认选中“值是数字则进行-1、-0”。
* 变更 监控Proxy模式 为被动模式，提升交互体验感。
* 新增相同数据包只扫描一次。算法：MD5(url+参数名)，如果是post包，值变化也不会重新扫描，需要参数名变化才会再次扫描。


**********
### 2022-2-13
#### xia SQL 1.4
* 更新了 一个选项，如果值是纯数字的话就进行-1，-0
![image](https://user-images.githubusercontent.com/30351807/153725862-8ec9e92f-66b5-4d5c-9c3e-fb18f5afaa94.png)


**********
### 2022-2-11
#### xia SQL 1.3
* 更新了 原始包的长度和两个单引号的长度相同且和一个单引号的长度不同就返回 ✔️ ==> ？

![image](https://user-images.githubusercontent.com/30351807/153590052-42293c4a-7a85-4740-b29e-209a7c27d403.png)


**********
### 2022-2-11
#### xia SQL 1.2
* 更新支持json格式

![image](https://user-images.githubusercontent.com/30351807/153567877-479a0e15-9d6c-43f5-84d9-80c5dfb6fd03.png)


**********
### 2022-2-10
#### xia SQL 1.1
* 更新了序列号
* 更新了有变化 打勾
* 更新了如果那个数据包没有参数，那就忽略。这样开 proxy 模式 就不会一堆包了。

![image](https://user-images.githubusercontent.com/30351807/153390045-2b3769f6-151b-45c0-a555-53cda4fef2f2.png)


**********
# 图片展示

![image](https://user-images.githubusercontent.com/30351807/153139897-08e6b69b-f129-4fab-a62e-037351d7c60f.png)

![image](https://user-images.githubusercontent.com/30351807/153139950-a4f51f4b-e39d-459d-91b8-e326c2c74c29.png)


![image](https://user-images.githubusercontent.com/30351807/153139522-b9af5d35-36a3-4204-b2f4-7b6a11253d41.png)
