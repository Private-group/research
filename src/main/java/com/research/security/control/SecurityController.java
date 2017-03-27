package com.research.security.control;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.research.security.bean.User;
import com.research.security.dto.AuthorityDto;
import com.research.security.service.CacheService;
import com.research.security.service.SecurityService;
import com.research.security.util.RSAUtil;




@RestController
public class SecurityController {
	
	@Autowired
	private SecurityService securityService;
	
	@Autowired
	private CacheService cacheService;
	
	/**
	 * 登陆验证
	 * @param vo
	 * @return
	 * @throws Exception 
	 */
    @RequestMapping(value = "/login")
    public boolean login(@Validated User vo) throws Exception {
    	AuthorityDto authorityDto = securityService.vlidateCreateKey(vo.getUserName(), RSAUtil.decodePassword(vo.getPassword()));
    	//返回公匙
    	authorityDto.getPubKey();
    	
    	//继续验证私匙  key验证
    	String priKeyKey = "key"+vo.getUserName();
    	String priKey = cacheService.get(priKeyKey);
    	if(StringUtils.isEmpty(priKey)) {
    		throw new Exception("用户名或密码错误！");
    	}
    	cacheService.remove(priKeyKey);
    	boolean flg = securityService.validateKey(vo.getUserName(), RSAUtil.decodePassword(vo.getPassword(), priKey));
    	
        return flg;
    }

}
