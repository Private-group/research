package com.research.security.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.dao.SaltSource;
import org.springframework.security.authentication.encoding.MessageDigestPasswordEncoder;
import org.springframework.util.StringUtils;

import com.research.security.bean.User;
import com.research.security.dto.AuthorityDto;
import com.research.security.util.RSAUtil;



public class SecurityService {
	
	@Autowired
	private MessageDigestPasswordEncoder passwordEncoder;
	
	@Autowired
	private SaltSource saltSource;
	
	@Autowired
	private CacheService cacheService;
	
	@Autowired
	private UserService userService;

	
	/**
	 * 登录验证及获取公匙、私匙
	 * @throws Exception 
	 */
	public AuthorityDto vlidateCreateKey(String loginId, String password) throws Exception  {
		AuthorityDto authorityDto = new AuthorityDto();
		String encodedPassword = encodePassword(password);
		List<User> users = userService.queryByLoginId(loginId);
		if(users.size() > 0) {
			User user = users.get(0);
			String pubKey = null;
			String priKey = null;
			if(user.getPassword() != null && !"".equals(user.getPassword()) && encodedPassword.equals(user.getPassword())) {
				//生成公匙、私匙
				String[] keys = RSAUtil.genKeyPairs();
				pubKey = keys[0];
				priKey = keys[1];
				cacheService.set("key"+user.getUserName(), priKey, 3);// 设置3秒缓存私匙
			} 
			if(pubKey != null) {
				authorityDto.setPubKey(pubKey);//返回公匙
				return authorityDto;
			}
		} 
		throw new Exception("登陆验证失败，用户名"+ loginId);
	}
	
	
	/**
	 * key验证
	 * @throws Exception 
	 */
	public boolean validateKey(String loginId, String password) throws Exception  {
		String encodedPassword = encodePassword(password);
		List<User> users = userService.queryByLoginId(loginId);
		if(users.size() > 0) {
			User user = users.get(0);
			if(user.getPassword() != null && !"".equals(user.getPassword()) && encodedPassword.equals(user.getPassword())) {
				return true;
			} 
		} 
		throw new Exception("登陆验证失败，用户名"+ loginId);
	}
	
	
	
	
	/**
	 * 密码加密
	 * @param password
	 * @return
	 * @throws Exception 
	 */
	public String encodePassword(String password) throws Exception {
		if(password == null || password.equals("")) {
			throw new Exception("密码不能为空");
		}
		return passwordEncoder.encodePassword(password, saltSource.getSalt(null));
	}
	
	
	
	
	

}
