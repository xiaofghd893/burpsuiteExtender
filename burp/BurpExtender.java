package burp;

import org.omg.CosNaming.IstringHelper;

import java.awt.*;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IMessageEditorController, IHttpListener
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private JSplitPane splitPane2;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IHttpRequestResponse currentlyDisplayedItem;
    private PrintWriter stdout;
    private final List<LogEntry> log = new ArrayList<>();
    private String[] URLS = new String[5];  //需要填入的要检测的域名
    private final LinkedTreeNode WebTree = new LinkedTreeNode(new NodeData("0","0","0"));  //存储网站目录，文件，值的树的头结点
    private final List<String> TestValue = new ArrayList<>();  //存储需要测试的值
    private final List<IHttpRequestResponse> Aims = new ArrayList<>();    //存储有sql注入的请求

    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;

        helpers = callbacks.getHelpers();

        //输出对象
        stdout = new PrintWriter(callbacks.getStdout(),true);

        // 设置插件名字
        callbacks.setExtensionName("CheckSqlInjection");

        //创建界面
        SwingUtilities.invokeLater(() -> {
            //整体分成上下两块
            splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

            //上半部分再分成左右两块
            splitPane2 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

            //上边左边区域
            JPanel panel = new JPanel();
            panel.setLayout(new BorderLayout());
            JPanel panel1 = new JPanel();
            //输入网址区域
            JTextField urlTxt = new JTextField(20);
            urlTxt.setText("dvwa.com;baidu.com");
            //按钮
            JButton applyBT = new JButton();

            applyBT.addActionListener(e -> {
                URLS = urlTxt.getText().split(";");
                //添加网址进树
                List<LinkedTreeNode> urls = new ArrayList<>();
                WebTree.setParent(null);
                for(String url : URLS)
                    WebTree.addChildNodeList(new LinkedTreeNode(new NodeData("0",url,"dir")));
            });
            applyBT.setText("apply");

            /*JButton TravelBT = new JButton();
            TravelBT.addActionListener(e -> {
                WebTree.Travel(stdout);
                stdout.println(WebTree.ChildNodeNum);
            });
            TravelBT.setText("travel");
            panel.add(TravelBT);*/

            panel1.add(urlTxt);
            panel1.add(applyBT);
            panel.add(panel1,BorderLayout.NORTH);
            splitPane2.setLeftComponent(panel);

            //上边右边区域，显示type,url
            Table logTable = new Table(BurpExtender.this);
            JScrollPane scrollPane = new JScrollPane(logTable);

            splitPane2.setRightComponent(scrollPane);
            splitPane.setLeftComponent(splitPane2);

            //下边区域，显示request和response
            JTabbedPane tabs = new JTabbedPane();
            requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
            responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
            tabs.addTab("Request", requestViewer.getComponent());
            tabs.addTab("Response", responseViewer.getComponent());
            splitPane.setRightComponent(tabs);

            // customize our UI components
            callbacks.customizeUiComponent(splitPane);
            callbacks.customizeUiComponent(splitPane2);
            callbacks.customizeUiComponent(panel);
            callbacks.customizeUiComponent(panel1);
            callbacks.customizeUiComponent(urlTxt);
            callbacks.customizeUiComponent(applyBT);
            callbacks.customizeUiComponent(applyBT);
            callbacks.customizeUiComponent(logTable);
            callbacks.customizeUiComponent(scrollPane);

            callbacks.customizeUiComponent(tabs);

            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(BurpExtender.this);

            // register ourselves as an HTTP listener
            callbacks.registerHttpListener(BurpExtender.this);
        });
    }

    //
    // implement ITab
    //

    @Override
    public String getTabCaption()
    {
        return "Logger";
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
        //只允许proxy模块流量
        if(callbacks.TOOL_PROXY==toolFlag){
            // 只监听request
            if (!messageIsRequest)
            {
                // create a new log entry with the message details
                synchronized(log)
                {
                    //遍历请求的目录，文件，值，看是否相同，相同则不检测
                    getUrlAndDirAndParameter(messageInfo);
                    if(TestValue.size()!=0) {
                        sentMessage(messageInfo);
                        TestValue.clear();
                    }
                    //判断是否有漏洞，有则添加到面版中
                    if(Aims.size()!=0){
                        for(IHttpRequestResponse L : Aims){
                            int row = log.size();
                            log.add(new LogEntry("sqlInjection",callbacks.saveBuffersToTempFiles(L),
                                    helpers.analyzeRequest(L).getUrl()));
                            fireTableRowsInserted(row,row);
                        }
                        Aims.clear();
                    }
                }
            }
        }
    }

    //获取并处理请求中目录，文件，值，请求方法，再发送到Judge函数
    public void getUrlAndDirAndParameter(IHttpRequestResponse message){
        String url = helpers.analyzeRequest(message).getUrl().toString();
        String method = helpers.analyzeRequest(message).getMethod();
        String host = message.getHttpService().getHost();
        String pattern = "([0-9](/\\w*(\\.\\w*)?)+)";
        Pattern r = Pattern.compile(pattern);
        Matcher m = r.matcher(url);

        if(m.find()){
            String mTemp = m.group();
            if(m.group().startsWith("/", m.group().length()-1)){
                mTemp = m.group()+"index";
            }
            else{
                pattern = "(?i)((js)|(css)|(jpg)|(gif)|(png))";
                r = Pattern.compile(pattern);
                m = r.matcher(mTemp.split("/")[mTemp.split("/").length-1]);
                if(m.find())
                    return;
            }
            Judge(host,mTemp.split("/"),method,helpers.analyzeRequest(message).getParameters());
        }
    }

    //判断这个请求是否检测过了
    public void Judge(String Host, String[] dirs, String method,List<IParameter> parameter){
        int Flag=0;  //辅助判断目录，值是否存在的参数
        LinkedTreeNode NextNode = null;  //树节点
        List<LinkedTreeNode> nextNodeList = WebTree.getChildNodeList();
        for(LinkedTreeNode urlClass : nextNodeList) {
            if (Host.contains(urlClass.getData().value)){
                Flag = 1;
                NextNode = urlClass;
                break;
            }
        }
        if(Flag==1){
            for(int i=1;i<dirs.length;i++){
                Flag = 0;
                if(NextNode.ChildNodeNum!=0){
                    for(LinkedTreeNode dir : NextNode.getChildNodeList()){
                        if(dir.getData().value.equals(dirs[i]) && dir.getData().method.equals(method)){
                            NextNode = dir;
                            //比较参数
                            Flag = 1;
                            //最后一个参数，做添加值操作
                            if(i==dirs.length-1){
                                //判断是否是文件和目录同名
                                if(dir.getData().type.equals("file")) {
                                    /*LinkedTreeNode L = null;*/
                                    for (IParameter P : parameter) {
                                        if (P.getType() == IParameter.PARAM_BODY || P.getType() == IParameter.PARAM_URL) {
                                            if(NextNode.getChildNodeList().size()!=0){
                                                for (LinkedTreeNode L : NextNode.getChildNodeList()) {
                                                    if (P.getName().equals(L.getData().value)) {
                                                        Flag = 0;
                                                        break;
                                                    }
                                                }
                                                if(Flag!=0){
                                                    TestValue.add(P.getName());
                                                    NextNode.addChildNodeList(new LinkedTreeNode(new NodeData(method, P.getName(), "value")));
                                                }
                                                else Flag = 1;
                                            }
                                            else {
                                                for (IParameter p1 : parameter){
                                                    if (p1.getType() == IParameter.PARAM_BODY || p1.getType() == IParameter.PARAM_URL){
                                                        TestValue.add(p1.getName());
                                                        NextNode.addChildNodeList(new LinkedTreeNode(new NodeData(method, p1.getName(), "value")));
                                                    }
                                                }
                                                return;
                                            }
                                        }
                                    }
                                    return;
                                }
                                else {
                                    Flag = 0;
                                    continue;
                                }
                            }
                            break;
                        }
                    }
                }
                if(Flag==0){
                    int k;
                    for(int j=i;j<dirs.length;j++){
                        if(j==dirs.length-1){
                            k = NextNode.addChildNodeList(new LinkedTreeNode(new NodeData(method,dirs[j],"file")));
                            NextNode = NextNode.getChildNodeList().get(k);
                        }
                        else{
                            k = NextNode.addChildNodeList(new LinkedTreeNode(new NodeData(method,dirs[j],"dirs")));
                            NextNode = NextNode.getChildNodeList().get(k);
                        }
                    }
                    for (IParameter I : parameter)
                        if(I.getType()==IParameter.PARAM_BODY||I.getType()==IParameter.PARAM_URL){
                            NextNode.addChildNodeList(new LinkedTreeNode(new NodeData(method,I.getName(),"value")));
                            TestValue.add(I.getName());
                        }
                    return;
                }
            }
        }
    }

    //发送请求
    public void sentMessage(IHttpRequestResponse message){
        List<IParameter> iParameter = helpers.analyzeRequest(message).getParameters();
        /*if(Aims.size()!=0) Aims.clear();*/   //test
        IParameter IParameterTemp;
        byte[] RequestTemp;
        IHttpRequestResponse TEMP;
        for(String temp : TestValue){
            for (IParameter parameter : iParameter) {
                if (temp.equals(parameter.getName())) {
                    IParameterTemp = helpers.buildParameter(temp, parameter.getValue() + "'", parameter.getType());
                    RequestTemp = helpers.updateParameter(message.getRequest(), IParameterTemp);
                    TEMP = callbacks.makeHttpRequest(message.getHttpService(), RequestTemp);
                    if (checkResponseBody(TEMP))
                        Aims.add(TEMP);
                }
            }
        }
    }

    //判断请求是否有漏洞
    public boolean checkResponseBody(IHttpRequestResponse message){
        IResponseInfo A = helpers.analyzeResponse(message.getResponse());
        int BodyInt = A.getBodyOffset();
        String Body =helpers.bytesToString(Arrays.copyOfRange(message.getResponse(),BodyInt,message.getResponse().length));
        String pattern = "(?i)((SQL syntax)|(Warning.*mssql_)|(Microsoft Access Driver)|(Oracle error)|(DB2 SQL error)|(SQLite.Exception))";

        Pattern r = Pattern.compile(pattern);
        Matcher m = r.matcher(Body);
        return m.find();
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
        return 2;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "Vulnerability type";
            case 1:
                return "URL";
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
                return logEntry.type;
            case 1:
                return logEntry.url.toString();
            default:
                return "";
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
        final String type;
        final IHttpRequestResponsePersisted requestResponse;
        final URL url;

        LogEntry(String type,IHttpRequestResponsePersisted requestResponse, URL url)
        {
            this.type = type;
            this.requestResponse = requestResponse;
            this.url = url;
        }
    }
}