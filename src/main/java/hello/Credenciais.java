package hello;

import java.io.Serializable;

public class Credenciais implements Serializable {
	private static final long serialVersionUID = 1L;
	
	private String username;
	private String password;
	
	public Credenciais(String username, String senha) {
		this.username = username;
		this.password = senha;
	}
	
	
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getSenha() {
		return password;
	}
	public void setSenha(String password) {
		this.password = password;
	}
}