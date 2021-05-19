package org.committee.insCCP.dataSets;

public class User {
	
	public String id;
	
	public String password_md5;
	
	public String nickName;
	
	public User(String id, String password_md5, String nickName) {
		this.id = id;
		
		this.password_md5 = password_md5;
		
		this.nickName = nickName;
	}
	
	@Override
	public String toString() {
		return this.nickName + "@" + this.id;
	}
}
