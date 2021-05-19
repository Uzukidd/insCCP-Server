package org.committee.insCCP.servers;

import java.nio.channels.AsynchronousSocketChannel;

import org.committee.insCCP.dataSets.User;

public class OnlineUser {
	public final User user;
	
	public AsynchronousSocketChannel sc;
	
	public String publicKey;
	//For receiving
	
	public String privateKey;
	//For broadcasting
	
	public OnlineUser(AsynchronousSocketChannel sc, String publicKey, String privateKey, User user) {
		this.sc = sc;
		
		this.publicKey = publicKey;
		
		this.privateKey = privateKey;
		
		this.user = user;
	}
}
