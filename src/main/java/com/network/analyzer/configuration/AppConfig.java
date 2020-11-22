package com.network.analyzer.configuration;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration
@EnableScheduling
public class AppConfig {

    @Bean
    public FilterRegistrationBean<AccessOriginFilter> accessOriginFilterFilterRegistrationBean() {
        FilterRegistrationBean<AccessOriginFilter> registrationBean
                = new FilterRegistrationBean<>();

        registrationBean.setFilter(new AccessOriginFilter());
        registrationBean.addUrlPatterns("*");
        registrationBean.setOrder(-101);

        return registrationBean;
    }
}
