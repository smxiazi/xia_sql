package burp;

import jdk.internal.org.objectweb.asm.tree.analysis.Value;

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


public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener, IMessageEditorController
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private final List<LogEntry> log2 = new ArrayList<LogEntry>();
    private final List<LogEntry> log3 = new ArrayList<LogEntry>();//用于展现
    private IHttpRequestResponse currentlyDisplayedItem;
    public PrintWriter stdout;
    int switchs = 1; //开关 0关 1开
    int clicks_Repeater=64;//64是监听 0是关闭
    int clicks_Proxy=0;//4是监听 0是关闭
    int conut = 0; //记录条数
    int log_id = 0; //用于判断目前选中的数据包
    public AbstractTableModel model = new MyModel();
    int original_data_len;//记录原始数据包的长度
    int is_int = 0; //开关 0关 1开;//记录原始数据包的长度



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
        this.stdout.println("version:1.4");



        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("xia SQL");

        // create our UI
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {

                // main split pane
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                // table of log entries
                Table logTable = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logTable); //给列表添加滚动条
                //splitPane.setLeftComponent(scrollPane); //添加在上面

                //test
                JPanel jp=new JPanel();
                JLabel jl=new JLabel("==>");    //创建一个标签

                //Object[][] tableDate=new Object[5][3];
                //String[] name={"参数","payload","响应包长度"};
                //JTable table=new JTable(tableDate,name);
                //AbstractTableModel model = new MyModel();
                Table_log2 table=new Table_log2(model);
                JScrollPane pane=new JScrollPane(table);//给列表添加滚动条

                jp.add(scrollPane);    //将表格加到面板
                jp.add(jl);    //将标签添加到面板
                jp.add(pane);    //将表格加到面板

                //侧边复选框
                JPanel jps=new JPanel();
                jps.setLayout(new GridLayout(6, 1)); //六行一列
                JLabel jls=new JLabel("<html>插件名：瞎注 blog:www.nmd5.com<br>后台发送完成请求后才显示响应包。<br>感谢名单：Moonlit、阿猫阿狗、Shincehor</html>");    //创建一个标签
                JCheckBox chkbox1=new JCheckBox("启动插件", true);    //创建指定文本和状态的复选框
                JCheckBox chkbox2=new JCheckBox("监控Repeater",true);    //创建指定文本的复选框
                JCheckBox chkbox3=new JCheckBox("监控Proxy");    //创建指定文本的复选框
                JCheckBox chkbox4=new JCheckBox("值是数字则进行-1、-0");    //创建指定文本的复选框
                //chkbox4.setEnabled(false);//设置为不可以选择

                JButton btn1=new JButton("清空列表");    //创建JButton对象

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
                btn1.addActionListener(new ActionListener() {//清空列表
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        log.clear();//清除log的内容
                        log2.clear();//清除log2的内容
                        log3.clear();//清除log3的内容
                        fireTableRowsInserted(log.size(), log.size());//刷新列表中的展示
                        model.fireTableRowsInserted(log3.size(), log3.size());//刷新列表中的展示
                    }
                });

                jps.add(jls);
                jps.add(chkbox1);
                jps.add(chkbox2);
                jps.add(chkbox3);
                jps.add(chkbox4);
                jps.add(btn1);
                jp.add(jps);

                splitPane.setLeftComponent(jp);


                // tabs with request/response viewers
                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                splitPane.setRightComponent(tabs);//添加在下面

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
            if(toolFlag == clicks_Repeater || toolFlag == clicks_Proxy){//监听Repeater和Proxy
                // only process responses
                if (!messageIsRequest)
                {
                    // create a new log entry with the message details
                    synchronized(log)
                    {
                        //用于判断是否要处理这个请求
                        List<IParameter>paraLists= helpers.analyzeRequest(messageInfo).getParameters();
                        for (IParameter para : paraLists){// 循环获取参数，判断类型，再构造新的参数，合并到新的请求包中。
                            if (para.getType() == 0 || para.getType() == 1 || para.getType() == 6) { //getTpe()就是来判断参数是在那个位置的
                                conut += 1;
                                int row = log.size();
                                original_data_len = callbacks.saveBuffersToTempFiles(messageInfo).getResponse().length;//更新原始数据包的长度
                                log.add(new LogEntry(conut,toolFlag, callbacks.saveBuffersToTempFiles(messageInfo),helpers.analyzeRequest(messageInfo).getUrl(),"","",""));
                                fireTableRowsInserted(row, row);
                                break;
                            }
                        }

                        //处理参数
                        List<IParameter>paraList= helpers.analyzeRequest(messageInfo).getParameters();
                        byte[] new_Request = messageInfo.getRequest();

                        for (IParameter para : paraList){// 循环获取参数
                            //payload
                            ArrayList<String> payloads = new ArrayList<>();
                            payloads.add("'");
                            payloads.add("''");

                            if (para.getType() == 0 || para.getType() == 1 || para.getType() == 6){ //getTpe()就是来判断参数是在那个位置的
                                String key = para.getName();//获取参数的名称
                                String value = para.getValue();//获取参数的值
                                stdout.println(key+":"+value);//输出原始的键值数据

                                if(is_int == 1){//开关，用于判断是否要开启-1、-0的操作
                                    if (value.matches("[0-9]+")) {//用于判读参数的值是否为存数字
                                        payloads.add("-1");
                                        payloads.add("-0");
                                    }
                                }


                                int change = 0; //用于判断返回包长度是否一致、保存第一次请求响应的长度
                                for (String payload : payloads) {
                                    stdout.println(key+":"+value+payload);//输出添加payload的键和值
                                    IHttpService iHttpService = messageInfo.getHttpService();

                                    //新的请求包
                                    IHttpRequestResponse requestResponse; //用于过if内的变量
                                    if(para.getType() == 6){
                                        //json格式
                                        List<String> headers = helpers.analyzeRequest(messageInfo).getHeaders();

                                        String newBody = "{"; //json body的内容

                                        for (IParameter paras : paraList){//循环所以参数，用来自定义json格式body做准备
                                            if(paras.getType() == 6) {//只要json格式的数据
                                                if(key == paras.getName() && value == paras.getValue()){//判断现在的键和值是否是需要添加payload的键和值
                                                    newBody += "\""+paras.getName() + "\":" + "\""+paras.getValue()+payload+"\",";//构造json的body
                                                }else {
                                                    newBody += "\""+paras.getName() + "\":" + "\""+paras.getValue()+"\",";//构造json的body
                                                }
                                            }
                                        }
                                        newBody = newBody.substring(0,newBody.length()-1); //去除最后一个,
                                        newBody += "}";//json body的内容

                                        byte[] bodyByte = newBody.getBytes();
                                        byte[] new_Requests = helpers.buildHttpMessage(headers, bodyByte); //关键方法
                                        requestResponse = callbacks.makeHttpRequest(iHttpService,new_Requests);//发送请求
                                    }else {
                                        //不是json格式
                                        IParameter newPara = helpers.buildParameter(key, value+payload, para.getType()); //构造新的参数
                                        byte[] newRequest = helpers.updateParameter(new_Request,newPara);//更新请求包的参数
                                        requestResponse = callbacks.makeHttpRequest(iHttpService,newRequest);//发送请求
                                    }

                                    //新的返回包
                                    //IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(requestResponse.getResponse());
                                    //List<String> response1_header_list = analyzeResponse1.getHeaders();

                                    //判断数据长度是否会变化
                                    String change_sign;//第二个表格中年 变化 的内容
                                    if(payload == "'" || payload == "-1" || change == 0){
                                        change = requestResponse.getResponse().length;//保存第一次请求响应的长度
                                        change_sign = "";
                                    }else{
                                        if(change != requestResponse.getResponse().length){//判断第一次的长度和现在的是否不同
                                            if(payload == "''" && requestResponse.getResponse().length == original_data_len || payload == "-0" && requestResponse.getResponse().length == original_data_len){//判断两个单引号的长度和第一次的不一样且和原始包的长度一致
                                                //原始包的长度和两个双引号的长度相同且和一个单引号的长度不同
                                                change_sign = "✔ ==> ?";
                                            }else{
                                                //第一次的包和第二次包的长度不同
                                                change_sign = "✔";
                                            }
                                        }else {
                                            //第一次包和第二次包的长度一样
                                            change_sign = "";
                                        }
                                    }
                                    //把响应内容保存在log2中
                                    log2.add(new LogEntry(conut,toolFlag, callbacks.saveBuffersToTempFiles(requestResponse),helpers.analyzeRequest(requestResponse).getUrl(),key,value+payload,change_sign));

                                }

                            }
                        }

                    }
                }
            }

        }

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
        return 4;
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
            return 4;
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
            log_id = logEntry.id;
            //stdout.println(log_id);//输出目前选中的行数
            log3.clear();
            for (int i = 0; i < log2.size(); i++) {//筛选出目前选中的原始数据包--》衍生出的带有payload的数据包
                 if(log2.get(i).id==log_id){
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


        LogEntry(int id,int tool, IHttpRequestResponsePersisted requestResponse, URL url,String parameter,String value,String change)
        {
            this.id = id;
            this.tool = tool;
            this.requestResponse = requestResponse;
            this.url = url;
            this.parameter = parameter;
            this.value = value;
            this.change = change;
        }
    }


}
