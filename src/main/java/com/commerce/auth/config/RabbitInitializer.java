package com.commerce.auth.config;

/*
@Author Didot
Created on 26/07/2026
@Last Modified on 26/07/2026 22:44
Version 1.0
*/

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.core.AmqpAdmin;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class RabbitInitializer {


    private final AmqpAdmin amqpAdmin;


    @PostConstruct
    public void init(){

        amqpAdmin.declareExchange(
                new TopicExchange(
                        "auth.events",
                        true,
                        false
                )
        );

    }

}