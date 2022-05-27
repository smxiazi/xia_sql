package burp;


import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import java.awt.*;
import java.awt.event.ItemListener;
import javax.swing.JMenuItem;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JTextArea;


public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener,IScannerCheck, IMessageEditorController,IContextMenuFactory
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();//记录原始流量
    private final List<LogEntry> log2 = new ArrayList<LogEntry>();//记录攻击流量
    private final List<LogEntry> log3 = new ArrayList<LogEntry>();//用于展现
    private final List<Request_md5> log4_md5 = new ArrayList<Request_md5>();//用于存放数据包的md5
    private IHttpRequestResponse currentlyDisplayedItem;
    public PrintWriter stdout;
    int switchs = 1; //开关 0关 1开
    int clicks_Repeater=0;//64是监听 0是关闭
    int clicks_Proxy=0;//4是监听 0是关闭
    int conut = 0; //记录条数
    String data_md5_id; //用于判断目前选中的数据包
    public AbstractTableModel model = new MyModel();
    int original_data_len;//记录原始数据包的长度
    int is_int = 1; //开关 0关 1开;//纯数据是否进行-1，-0
    String temp_data; //用于保存临时内容
    int JTextArea_int = 0;//自定义payload开关  0关 1开
    String JTextArea_data_1 = "";//文本域的内容
    int diy_payload_1 = 1;//自定义payload空格编码开关  0关 1开
    int diy_payload_2 = 0;//自定义payload值置空开关  0关 1开
    int select_row = 0;//选中表格的行数
    Table logTable; //第一个表格框
    int is_cookie = -1;//cookie是否要注入，-1关闭 2开启。





    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        //输出
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stdout.println("hello xia sql!");
        this.stdout.println("你好 欢迎使用 瞎注!");
        this.stdout.println("version:2.4");



        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("xia SQL V2.4");

        // create our UI
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {

                // main split pane
                splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                JSplitPane splitPanes = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                JSplitPane splitPanes_2 = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                // table of log entries
                logTable = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logTable); //给列表添加滚动条


                //test
                JPanel jp=new JPanel();
                JLabel jl=new JLabel("==>");    //创建一个标签

                Table_log2 table=new Table_log2(model);
                JScrollPane pane=new JScrollPane(table);//给列表添加滚动条

                jp.add(scrollPane);    //将表格加到面板
                jp.add(jl);    //将标签添加到面板
                jp.add(pane);    //将表格加到面板

                //侧边复选框
                JPanel jps=new JPanel();
                jps.setLayout(new GridLayout(15, 1)); //六行一列
                JLabel jls=new JLabel("插件名：瞎注");    //创建一个标签
                JLabel jls_1=new JLabel("blog:www.nmd5.com");    //创建一个标签
                JLabel jls_2=new JLabel("版本：xia SQL V2.4");    //创建一个标签
                JLabel jls_3=new JLabel("感谢名单：Moonlit、阿猫阿狗、Shincehor");    //创建一个标签
                JCheckBox chkbox1=new JCheckBox("启动插件", true);    //创建指定文本和状态的复选框
                JCheckBox chkbox2=new JCheckBox("监控Repeater");    //创建指定文本的复选框
                JCheckBox chkbox3=new JCheckBox("监控Proxy");    //创建指定文本的复选框
                JCheckBox chkbox4=new JCheckBox("值是数字则进行-1、-0",true);    //创建指定文本的复选框
                JLabel jls_4=new JLabel("修改payload后记得点击加载");    //创建一个标签
                JCheckBox chkbox5=new JCheckBox("自定义payload");    //创建指定文本的复选框
                JCheckBox chkbox6=new JCheckBox("自定义payload中空格url编码",true);    //创建指定文本的复选框
                JCheckBox chkbox7=new JCheckBox("自定义payload中参数值置空");    //创建指定文本的复选框
                JCheckBox chkbox8=new JCheckBox("测试Cookie");    //创建指定文本的复选框

                //chkbox4.setEnabled(false);//设置为不可以选择

                JButton btn1=new JButton("清空列表");    //创建JButton对象
                JButton btn2=new JButton("加载/重新加载payload");    //创建JButton对象

                //自定义payload区
                JPanel jps_2=new JPanel();
                JTextArea jta=new JTextArea("%df' and sleep(3)%23\n'and '1'='1",18,16);
                //jta.setLineWrap(true);    //设置文本域中的文本为自动换行
                jta.setForeground(Color.BLACK);    //设置组件的背景色
                jta.setFont(new Font("楷体",Font.BOLD,16));    //修改字体样式
                jta.setBackground(Color.LIGHT_GRAY);    //设置背景色
                jta.setEditable(false);//不可编辑状态
                JScrollPane jsp=new JScrollPane(jta);    //将文本域放入滚动窗口
                jps_2.add(jsp);    //将JScrollPane添加到JPanel容器中

                //添加复选框监听事件
                chkbox1.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox1.isSelected()){
                            stdout.println("插件xia SQl启动");
                            switchs = 1;
                        }else {
                            stdout.println("插件xia SQL关闭");
                            switchs = 0;
                        }

                    }
                });
                chkbox2.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if (chkbox2.isSelected()){
                            stdout.println("启动 监控Repeater");
                            clicks_Repeater = 64;
                        }else {
                            stdout.println("关闭 监控Repeater");
                            clicks_Repeater = 0;
                        }
                    }
                });
                chkbox3.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox3.isSelected()) {
                            stdout.println("启动 监控Proxy");
                            clicks_Proxy = 4;
                        }else {
                            stdout.println("关闭 监控Proxy");
                            clicks_Proxy = 0;
                        }
                    }
                });
                chkbox4.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox4.isSelected()) {
                            stdout.println("启动 值是数字则进行-1、-0");
                            is_int = 1;
                        }else {
                            stdout.println("关闭 值是数字则进行-1、-0");
                            is_int = 0;
                        }
                    }
                });

                chkbox5.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox5.isSelected()) {
                            stdout.println("启动 自定义payload");
                            jta.setEditable(true);
                            jta.setBackground(Color.WHITE);    //设置背景色
                            JTextArea_int = 1;

                            if (diy_payload_1 == 1){
                                String temp_data = jta.getText();
                                temp_data = temp_data.replaceAll(" ","%20");
                                JTextArea_data_1 = temp_data;
                            }else {
                                JTextArea_data_1 = jta.getText();
                            }

                        }else {
                            stdout.println("关闭 自定义payload");
                            jta.setEditable(false);
                            jta.setBackground(Color.LIGHT_GRAY);    //设置背景色
                            JTextArea_int = 0;
                        }
                    }
                });

                chkbox6.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox6.isSelected()) {
                            stdout.println("启动 空格url编码");
                            diy_payload_1 = 1;

                            //空格url编码
                            String temp_data = jta.getText();
                            temp_data = temp_data.replaceAll(" ","%20");
                            JTextArea_data_1 = temp_data;
                        }else {
                            stdout.println("关闭 空格url编码");
                            diy_payload_1 = 0;

                            JTextArea_data_1 = jta.getText();
                        }
                    }
                });

                chkbox7.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox7.isSelected()) {
                            stdout.println("启动 自定义payload参数值置空");
                            diy_payload_2 = 1;
                        }else {
                            stdout.println("关闭 自定义payload参数值置空");
                            diy_payload_2 = 0;
                        }
                    }
                });

                chkbox8.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox8.isSelected()) {
                            stdout.println("启动 测试Cookie");
                            is_cookie = 2;
                        }else {
                            stdout.println("关闭 测试Cookie");
                            is_cookie = -1;
                        }
                    }
                });

                btn1.addActionListener(new ActionListener() {//清空列表
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        log.clear();//清除log的内容
                        log2.clear();//清除log2的内容
                        log3.clear();//清除log3的内容
                        log4_md5.clear();//清除log4的内容
                        conut = 0;
                        fireTableRowsInserted(log.size(), log.size());//刷新列表中的展示
                        model.fireTableRowsInserted(log3.size(), log3.size());//刷新列表中的展示
                    }
                });

                btn2.addActionListener(new ActionListener() {//加载自定义payload
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (diy_payload_1 == 1){
                            String temp_data = jta.getText();
                            temp_data = temp_data.replaceAll(" ","%20");
                            JTextArea_data_1 = temp_data;
                        }else {
                            JTextArea_data_1 = jta.getText();
                        }
                    }
                });

                jps.add(jls);
                jps.add(jls_1);
                jps.add(jls_2);
                jps.add(jls_3);
                jps.add(chkbox1);
                jps.add(chkbox2);
                jps.add(chkbox3);
                jps.add(chkbox4);
                jps.add(chkbox8);
                jps.add(btn1);
                jps.add(jls_4);
                jps.add(chkbox5);
                jps.add(chkbox6);
                jps.add(chkbox7);
                jps.add(btn2);






                // tabs with request/response viewers
                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());

                //jp.add(tabs);

                //右边
                splitPanes_2.setLeftComponent(jps);//上面
                splitPanes_2.setRightComponent(jps_2);//下面

                //左边
                splitPanes.setLeftComponent(jp);//上面
                splitPanes.setRightComponent(tabs);//下面

                //整体分布
                splitPane.setLeftComponent(splitPanes);//添加在左面
                splitPane.setRightComponent(splitPanes_2);//添加在右面
                splitPane.setDividerLocation(1000);//设置分割的大小

                // customize our UI components
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(pane);
                callbacks.customizeUiComponent(jps);
                callbacks.customizeUiComponent(jp);
                callbacks.customizeUiComponent(tabs);

                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);

                // register ourselves as an HTTP listener
                callbacks.registerHttpListener(BurpExtender.this);
                callbacks.registerScannerCheck(BurpExtender.this);
                callbacks.registerContextMenuFactory(BurpExtender.this);

            }
        });
    }
    //
    // implement ITab
    //

    @Override
    public String getTabCaption()
    {
        return "xia SQL";
    }

    @Override
    public Component getUiComponent()
    {
        return splitPane;
    }

    //
    // implement IHttpListener
    //




    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {

        if(switchs == 1){//插件开关
            if(toolFlag == clicks_Repeater || toolFlag == clicks_Proxy){//监听Repeater
                // only process responses
                if (!messageIsRequest)
                {
                    // create a new log entry with the message details
                    synchronized(log)
                    {
                        //BurpExtender.this.checkVul(messageInfo,toolFlag);
                        Thread thread = new Thread(new Runnable() {
                            public void run() {
                                try {
                                    BurpExtender.this.checkVul(messageInfo,toolFlag);
                                } catch (Exception ex) {
                                    ex.printStackTrace();
                                    BurpExtender.this.stdout.println(ex);
                                }
                            }
                        });
                        thread.start();
                    }
                }
            }

        }

    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        //右键发送按钮功能

        List<JMenuItem> listMenuItems = new ArrayList<JMenuItem>(1);
        if(invocation.getToolFlag() == IBurpExtenderCallbacks.TOOL_REPEATER || invocation.getToolFlag() == IBurpExtenderCallbacks.TOOL_PROXY){
            //父级菜单
            IHttpRequestResponse[] responses = invocation.getSelectedMessages();
            JMenuItem jMenu = new JMenuItem("Send to xia SQL");

            jMenu.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    if(switchs == 1) {
                        //不应在Swing事件调度线程中发出HTTP请求，所以需要创建一个Runnable并在 run() 方法中完成工作，后调用 new Thread(runnable).start() 来启动线程
                        Thread thread = new Thread(new Runnable() {
                            public void run() {
                                try {
                                    BurpExtender.this.checkVul(responses[0], 1024);
                                } catch (Exception ex) {
                                    ex.printStackTrace();
                                    BurpExtender.this.stdout.println(ex);
                                }
                            }
                        });
                        thread.start();
                    }else {
                        BurpExtender.this.stdout.println("插件xia SQL关闭状态！");
                    }

                }
            });

            listMenuItems.add(jMenu);


                                       }
            //BurpExtender.this.checkVul(responses,4);
        return listMenuItems;
    }

    private void checkVul(IHttpRequestResponse baseRequestResponse, int toolFlag){
            int is_add; //用于判断是否要添加扫描
            String change_sign_1 = ""; //用于显示第一个列表框的状态 变化 部分的内容

            //把当前url和参数进行md5加密，用于判断该url是否已经扫描过
            List<IParameter>paraLists= helpers.analyzeRequest(baseRequestResponse).getParameters();
            temp_data = String.valueOf(helpers.analyzeRequest(baseRequestResponse).getUrl());//url
            //stdout.println(temp_data);
            String[] temp_data_strarray=temp_data.split("\\?");
            String temp_data =(String) temp_data_strarray[0];//获取问号前面的字符串

            //用于判断页面后缀是否为静态文件
            if(toolFlag == 4 || toolFlag ==64){//流量是Repeater与proxy来的就对其后缀判断
                String[] static_file = {"jpg","png","gif","css","js","pdf","mp3","mp4","avi"};
                String[] static_file_1 =temp_data.split("\\.");
                String static_file_2 = static_file_1[static_file_1.length-1];//获取最后一个.内容
                //this.stdout.println(static_file_2);
                for(String i:static_file){
                    if(static_file_2.equals(i)){
                        this.stdout.println("当前url为静态文件："+temp_data+"\n");
                        return;
                    }
                }
            }

        //stdout.println(temp_data);

            String request_data = null;
            String[] request_datas;
            is_add = 0;
            for (IParameter para : paraLists){// 循环获取参数，判断类型，再构造新的参数，合并到新的请求包中。
                if (para.getType() == 0 || para.getType() == 1 || para.getType() == 6 || para.getType() == is_cookie) { //getTpe()就是来判断参数是在那个位置的
                    if(is_add == 0){
                        is_add = 1;
                    }
                    temp_data += "+"+para.getName();

                    //判断是否为json嵌套 考虑性能消耗，判断json嵌套 和 json中带列表的  才用正则处理
                    if(para.getType() == 6 && request_data == null){
                        try {
                            //stdout.println(helpers.bytesToString(baseRequestResponse.getRequest()));//查看数据包内容
                            request_data = helpers.bytesToString(baseRequestResponse.getRequest()).split("\r\n\r\n")[1];
                            //stdout.println(request_data);

                            //json嵌套
                            request_datas = request_data.split("\\{\"");
                            if(request_datas.length >2){
                                is_add = 2;
                            }
                            //json中有列表
                            request_datas = request_data.split("\":\\[");
                            if(request_datas.length >1){
                                is_add = 2;
                            }
                        } catch (Exception e) {
                            stdout.println(e);
                        }
                    }
                }
            }



            //url+参数进行编码
            temp_data += "+"+helpers.analyzeRequest(baseRequestResponse).getMethod();
            //this.stdout.println(temp_data);
            this.stdout.println("\nMD5(\""+temp_data+"\")");
            temp_data = MD5(temp_data);
            this.stdout.println(temp_data);



            for (Request_md5 i : log4_md5){
                if(i.md5_data.equals(temp_data)){//判断md5值是否一样，且右键发送过来的请求不进行md5验证
                    if(toolFlag == 1024){
                        temp_data = String.valueOf(System.currentTimeMillis());
                        this.stdout.println(temp_data);
                        temp_data = MD5(temp_data);
                        this.stdout.println(temp_data);
                    }else {
                        return;
                    }


                }
            }

            //用于判断是否要处理这个请求
            if (is_add != 0){
                log4_md5.add(new Request_md5(temp_data));//保存对应对md5
                stdout.println(is_add);
                stdout.println(request_data);

                conut += 1;
                int row = log.size();
                original_data_len = callbacks.saveBuffersToTempFiles(baseRequestResponse).getResponse().length;//更新原始数据包的长度

                log.add(new LogEntry(conut,toolFlag, callbacks.saveBuffersToTempFiles(baseRequestResponse),helpers.analyzeRequest(baseRequestResponse).getUrl(),"","","",temp_data,0,"run……"));
                fireTableRowsInserted(row, row);
            }

            //处理参数
            List<IParameter>paraList= helpers.analyzeRequest(baseRequestResponse).getParameters();
            byte[] new_Request = baseRequestResponse.getRequest();
            int json_count = -1;//记录json嵌套次数


            for (IParameter para : paraList){// 循环获取参数
                if(para.getType() == 6){
                    json_count += 1;//记录json嵌套次数
                }
                //payload
                ArrayList<String> payloads = new ArrayList<>();
                payloads.add("'");
                payloads.add("''");



                if (para.getType() == 0 || para.getType() == 1 || para.getType() == 6 || para.getType() == is_cookie){ //getTpe()就是来判断参数是在那个位置的
                    String key = para.getName();//获取参数的名称
                    String value = para.getValue();//获取参数的值
                    stdout.println(key+":"+value);//输出原始的键值数据

                    if(is_int == 1){//开关，用于判断是否要开启-1、-0的操作
                        if (value.matches("[0-9]+")) {//用于判读参数的值是否为纯数字
                            payloads.add("-1");
                            payloads.add("-0");
                        }
                    }

                    //自定义payload
                    if(JTextArea_int == 1){
                        String[] JTextArea_data = JTextArea_data_1.split("\n");
                        for(String a:JTextArea_data){
                            //stdout.println(a);
                            //stdout.println("------");
                            payloads.add(a);
                        }
                    }

                    int change = 0; //用于判断返回包长度是否一致、保存第一次请求响应的长度
                    for (String payload : payloads) {
                        int time_1 = 0,time_2 = 0;

                        if(JTextArea_int == 1){
                            //自定义payload //参数值为空
                            if(diy_payload_2 == 1){
                                if(payload != "'" && payload !="''" && payload != "-1" && payload != "-0"){
                                    value = "";
                                }
                            }
                        }

                        stdout.println(key+":"+value+payload);//输出添加payload的键和值
                        IHttpService iHttpService = baseRequestResponse.getHttpService();

                        //新的请求包
                        IHttpRequestResponse requestResponse = null; //用于过if内的变量
                        
                        if(para.getType() == 6){
                            List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
                            if(is_add ==1) {
                                //json格式
                                String newBody = "{"; //json body的内容

                                for (IParameter paras : paraList) {//循环所有参数，用来自定义json格式body做准备
                                    if (paras.getType() == 6) {//只要json格式的数据
                                        if (key == paras.getName() && value == paras.getValue()) {//判断现在的键和值是否是需要添加payload的键和值
                                            newBody += "\"" + paras.getName() + "\":" + "\"" + paras.getValue() + payload + "\",";//构造json的body
                                        } else {
                                            newBody += "\"" + paras.getName() + "\":" + "\"" + paras.getValue() + "\",";//构造json的body
                                        }
                                    }
                                }

                                newBody = newBody.substring(0, newBody.length() - 1); //去除最后一个,
                                newBody += "}";//json body的内容

                                byte[] bodyByte = newBody.getBytes();
                                byte[] new_Requests = helpers.buildHttpMessage(headers, bodyByte); //关键方法

                                time_1 = (int) System.currentTimeMillis();
                                requestResponse = callbacks.makeHttpRequest(iHttpService, new_Requests);//发送请求
                                time_2 = (int) System.currentTimeMillis();
                            }else if (is_add ==2){
                                //json嵌套
                                String[] request_data_temp = request_data.split(",");//用于临时保存切割的post体内容
                                String request_data_body = "";String request_data_body_temp = "";//修改后的body和需要临时编辑的字符串

                                for(int i=0;i < request_data_temp.length;i++){
                                    if(i==json_count){//判断现在修改的参数
                                        request_data_body_temp = request_data_temp[i];


                                        stdout.println(request_data_body_temp);
                                        //空列表如："classLevels":[]，跳过处理
                                        if(request_data_body_temp.contains(":[]")) {//判断是否为空列表
                                            json_count += 1;
                                            request_data_body += request_data_temp[i]+",";
                                            i += 1;
                                            request_data_body_temp = request_data_temp[i];
                                        }

                                        if(request_data_body_temp.contains("\":")){
                                            //判断字符串中是否有":，如果有则为正常json内容
                                            Pattern p = Pattern.compile(".*:\\s?\\[?\\s?(.*?$)");
                                            Matcher m = p.matcher(request_data_body_temp);
                                            if(m.find()){
                                                request_data_body_temp = m.group(1);//获取:后面的内容
                                            }
                                            if(request_data_body_temp.contains("\"")){//判断内容是否为字符串
                                                request_data_body_temp = request_data_temp[i];
                                                //修改内容，添加payload
                                                request_data_body_temp = request_data_body_temp.replaceAll("^(.*:.*?\")(.*?)(\"[^\"]*)$","$1$2"+payload+"$3");
                                                request_data_body+= request_data_body_temp +",";
                                            }else {
                                                request_data_body_temp = request_data_temp[i];
                                                //修改内容，添加payload
                                                request_data_body_temp = request_data_body_temp.replaceAll("^(.*:.*?)(\\d*)([^\"\\d]*)$","$1\"$2"+payload+"\"$3");
                                                request_data_body+= request_data_body_temp +",";
                                            }

                                        }else {
                                            //字符串中没有":，表示json格式中嵌套的列表
                                            if(request_data_body_temp.contains("\"")) {//判断内容是否为字符串
                                                //修改内容，添加payload
                                                request_data_body_temp = request_data_body_temp.replaceAll("^(\")(.*?)(\".*?)$","$1$2"+payload+"$3");
                                                request_data_body+= request_data_body_temp +",";
                                            }else {
                                                //不是字符串，则为纯数字
                                                request_data_body_temp = request_data_body_temp.replaceAll("^(\\d*)(.*?)$","\"$1"+payload+"\"$2");
                                                request_data_body+= request_data_body_temp +",";
                                            }


                                        }
                                        //stdout.println(request_data_body_temp);


                                    }else {
                                        request_data_body += request_data_temp[i]+",";
                                    }
                                }
                                request_data_body = request_data_body.substring(0, request_data_body.length() - 1); //去除最后一个,

                                byte[] bodyByte = request_data_body.getBytes();
                                byte[] new_Requests = helpers.buildHttpMessage(headers, bodyByte); //关键方法
                                time_1 = (int) System.currentTimeMillis();
                                requestResponse = callbacks.makeHttpRequest(iHttpService, new_Requests);//发送请求
                                time_2 = (int) System.currentTimeMillis();

                            }
                        }else {
                            //不是json格式
                            IParameter newPara = helpers.buildParameter(key,value + payload, para.getType()); //构造新的参数
                            byte[] newRequest = helpers.updateParameter(new_Request, newPara);//更新请求包的参数

                            time_1 = (int) System.currentTimeMillis();
                            requestResponse = callbacks.makeHttpRequest(iHttpService, newRequest);//发送请求
                            time_2 = (int) System.currentTimeMillis();

                        }

                        //判断数据长度是否会变化
                        String change_sign;//第二个表格中 变化 的内容
                        if(payload == "'" || payload == "-1" || change == 0){
                            change = requestResponse.getResponse().length;//保存第一次请求响应的长度
                            change_sign = "";
                        }else{
                            if(payload == "''" || payload == "-0" ){
                                if(change != requestResponse.getResponse().length){//判断第一次的长度和现在的是否不同
                                    if(payload == "''" && requestResponse.getResponse().length == original_data_len || payload == "-0" && requestResponse.getResponse().length == original_data_len){//判断两个单引号的长度和第一次的不一样且和原始包的长度一致
                                        //原始包的长度和两个双引号的长度相同且和一个单引号的长度不同
                                        change_sign = "✔ ==> ?";
                                        change_sign_1 = " ✔";
                                    }else{
                                        //第一次的包和第二次包的长度不同
                                        change_sign = "✔";
                                        change_sign_1 = " ✔";
                                    }
                                }else {
                                    //第一次包和第二次包的长度一样
                                    change_sign = "";
                                }
                            }else {
                                //自定义payload
                                if(time_2-time_1 >= 3000){
                                    //响应时间大于3秒
                                    change_sign = "time > 3";
                                    change_sign_1 = " ✔";
                                }else {
                                    change_sign = "diy payload";
                                }
                            }

                        }
                        //把响应内容保存在log2中
                        log2.add(new LogEntry(conut,toolFlag, callbacks.saveBuffersToTempFiles(requestResponse),helpers.analyzeRequest(requestResponse).getUrl(),key,value+payload,change_sign,temp_data,time_2-time_1,"end"));

                    }
                }
            }

        //用于更新是否已经跑完所有payload的状态
        for(int i = 0; i < log.size(); i++){
            if(temp_data.equals(log.get(i).data_md5)){
                log.get(i).setState("end!"+change_sign_1);
                //stdout.println("ok");
            }
        }

        //刷新第一个列表框
        //BurpExtender.this.fireTableRowsInserted(log.size(), log.size());
        BurpExtender.this.fireTableDataChanged();
        //第一个表格 继续选中之前选中的值
        BurpExtender.this.logTable.setRowSelectionInterval(BurpExtender.this.select_row-1,BurpExtender.this.select_row-1);



    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }
    //
    // extend AbstractTableModel
    //

    @Override
    public int getRowCount()
    {
        return log.size();

    }

    @Override
    public int getColumnCount()
    {
        return 5;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "#";
            case 1:
                return "来源";
            case 2:
                return "URL";
            case 3:
                return "返回包长度";
            case 4:
                return "状态";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return logEntry.id;
            case 1:
                return callbacks.getToolName(logEntry.tool);
            case 2:
                return logEntry.url.toString();
            case 3:
                return logEntry.requestResponse.getResponse().length;//返回响应包的长度
            case 4:
                return logEntry.state;
            default:
                return "";
        }
    }


    //model2
    class MyModel extends AbstractTableModel {

        @Override
        public int getRowCount()
        {
            return log3.size();
        }

        @Override
        public int getColumnCount()
        {
            return 5;
        }

        @Override
        public String getColumnName(int columnIndex)
        {
            switch (columnIndex)
            {
                case 0:
                    return "参数";
                case 1:
                    return "payload";
                case 2:
                    return "返回包长度";
                case 3:
                    return "变化";
                case 4:
                    return "用时";
                default:
                    return "";
            }
        }

        @Override
        public Class<?> getColumnClass(int columnIndex)
        {
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex)
        {
            LogEntry logEntry2 = log3.get(rowIndex);

            switch (columnIndex)
            {
                case 0:
                    return logEntry2.parameter;
                case 1:
                    return logEntry2.value;
                case 2:
                    return logEntry2.requestResponse.getResponse().length;//返回响应包的长度
                case 3:
                    return logEntry2.change;
                case 4:
                    return logEntry2.times;
                default:
                    return "";
            }
        }
    }




    //
    // implement IMessageEditorController
    // this allows our request/response viewers to obtain details about the messages being displayed
    //

    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }

    //
    // extend JTable to handle cell selection
    //

    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            data_md5_id = logEntry.data_md5;
            //stdout.println(log_id);//输出目前选中的行数
            select_row = logEntry.id;

            log3.clear();
            for (int i = 0; i < log2.size(); i++) {//筛选出目前选中的原始数据包--》衍生出的带有payload的数据包
                 if(log2.get(i).data_md5==data_md5_id){
                     log3.add(log2.get(i));
                 }
            }
            //刷新列表界面
            model.fireTableRowsInserted(log3.size(), log3.size());
            model.fireTableDataChanged();

            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }

    private class Table_log2 extends JTable
    {
        public Table_log2(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {

            // show the log entry for the selected row
            LogEntry logEntry = log3.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }

    //存放数据包的md5值，用于匹配该数据包已请求过
    private static class Request_md5
    {
        final String md5_data;

        Request_md5(String md5_data)
        {
            this.md5_data = md5_data;
        }
    }
    //
    // class to hold details of each log entry
    //
    private static class LogEntry
    {
        final int id;
        final int tool;
        final IHttpRequestResponsePersisted requestResponse;
        final URL url;
        final String parameter;
        final String value;
        final String change;
        final String data_md5;
        final int times;
        String state;


        LogEntry(int id,int tool, IHttpRequestResponsePersisted requestResponse, URL url,String parameter,String value,String change,String data_md5,int times,String state)
        {
            this.id = id;
            this.tool = tool;
            this.requestResponse = requestResponse;
            this.url = url;
            this.parameter = parameter;
            this.value = value;
            this.change = change;
            this.data_md5 = data_md5;
            this.times = times;
            this.state = state;
        }

        public String setState(String state){
            this.state = state;
            return this.state;
        }
    }

    public static String MD5(String key) {
        char hexDigits[] = {
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
        };
        try {
            byte[] btInput = key.getBytes();
            // 获得MD5摘要算法的 MessageDigest 对象
            MessageDigest mdInst = MessageDigest.getInstance("MD5");
            // 使用指定的字节更新摘要
            mdInst.update(btInput);
            // 获得密文
            byte[] md = mdInst.digest();
            // 把密文转换成十六进制的字符串形式
            int j = md.length;
            char str[] = new char[j * 2];
            int k = 0;
            for (int i = 0; i < j; i++) {
                byte byte0 = md[i];
                str[k++] = hexDigits[byte0 >>> 4 & 0xf];
                str[k++] = hexDigits[byte0 & 0xf];
            }
            return new String(str);
        } catch (Exception e) {
            return null;
        }
    }


}
