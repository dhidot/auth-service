package com.commerce.auth.event;

/*
@Author Didot
Created on 26/07/2026
@Last Modified on 26/07/2026 22:19
Version 1.0
*/

import com.commerce.auth.config.RabbitMQConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserEventPublisher {


    private final RabbitTemplate rabbitTemplate;


    public void publishUserRegistered(
            UserRegisteredEvent event
    ){

        rabbitTemplate.convertAndSend(
                RabbitMQConfig.AUTH_EXCHANGE,
                RabbitMQConfig.USER_REGISTERED_ROUTING_KEY,
                event
        );

    }

}