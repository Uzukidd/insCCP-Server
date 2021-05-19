package org.committee.insCCP.dataSets;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.committee.insCCP.externalDataLoaders.MySqlLoader;

public class UsersContainer {
	
	public Map<String, User> users = null;
	
	public MySqlLoader mysqlLoader = null;
	
	public static final UsersContainer instance = new UsersContainer();
	
	private UsersContainer() {
		this.init();
	}
	
	private void init() {
		
		try {
			mysqlLoader = new MySqlLoader();
		} catch (ClassNotFoundException | SQLException e) {
			e.printStackTrace();
		}
		
		this.clear();
		
		this.loadData();
	}
	
	public void clear() {
		if(users == null) users = new HashMap<>();
		
		users.clear();
	}
	
	public boolean connectFriend(String srcId, String dstId) {
		boolean res = true;
		this.mysqlLoader.connectFriend(srcId, dstId);
		return res;
	}
	
	public boolean deleteFriend(String srcId, String dstId) {
		boolean res = true;
		this.mysqlLoader.deleteFriend(srcId, dstId);
		return res;
	}
	
	public ArrayList<String> searchFriend(String srcId) {
		ArrayList<String> res = this.mysqlLoader.searchFriend(srcId);
		return res;
	}
	
	public ArrayList<String> searchApplyFriend(String srcId) {
		ArrayList<String> res = this.mysqlLoader.searchApplyFriend(srcId);
		return res;
	}
	
	public ArrayList<User> searchFriendAsUser(String srcId) {
		ArrayList<User> res = new ArrayList<User>();
		
		for(String id : this.mysqlLoader.searchFriend(srcId)) {
			res.add(this.users.get(id));
		}
		return res;
	}
	
	public ArrayList<User> searchApplyFriendAsUser(String srcId) {
		ArrayList<User> res = new ArrayList<User>();
		
		for(String id : this.mysqlLoader.searchApplyFriend(srcId)) {
			res.add(this.users.get(id));
		}
		return res;
	}
	
	public void loadData() {
		this.mysqlLoader.loadUsers(this.users);
	}
	
}
