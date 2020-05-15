package burp;

import org.omg.PortableServer.LIFESPAN_POLICY_ID;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class LinkedTreeNode {

    private NodeData mData;
    private LinkedTreeNode mParent;
    private final List<LinkedTreeNode> mChildNodeList = new ArrayList<>();
    public int ChildNodeNum = 0;

    LinkedTreeNode(NodeData Data){
        this.mData = Data;
    }

    public NodeData getData() {
        return mData;
    }

    public void setData(NodeData mData) {
        this.mData = mData;
    }

    public LinkedTreeNode getParent(){
        return mParent;
    }

    public List<LinkedTreeNode> getBrother(){
        return this.getParent().mChildNodeList;
    }

    public void setParent(LinkedTreeNode mParent) {
        this.mParent = mParent;
    }

    public List<LinkedTreeNode> getChildNodeList(){
        return mChildNodeList;
    }

    public int addChildNodeList(LinkedTreeNode ChildNode){
        ChildNode.setParent(this);//
        mChildNodeList.add(ChildNode);
        ChildNodeNum+=1;
        return mChildNodeList.size()-1;
    }

    //深度遍历
    public void Travel(PrintWriter stdout){
        stdout.println("value:"+this.getData().value+"\ttype:"+this.getData().type+"\tmethod:"+this.getData().method);
        if(this.getParent()!=null) stdout.println("Parent:"+this.getParent().getData().value);
        for(LinkedTreeNode Temp : this.getChildNodeList()){
            Temp.Travel(stdout);
        }
    }
}