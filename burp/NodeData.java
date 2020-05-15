package burp;

public class NodeData {
    public String method;  //请求方法
    public String value;   //值
    public String type;    //是目录还是文件还是参数

    public NodeData(String method, String value, String type){
        this.method = method;
        this.value = value;
        this.type = type;
    }
}
