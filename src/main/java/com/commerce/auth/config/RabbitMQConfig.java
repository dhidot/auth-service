package com.commerce.auth.config;

/*
@Author Didot
Created on 26/07/2026
@Last Modified on 26/07/2026 22:19
Version 1.0
*/

import jakarta.annotation.PostConstruct;
import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.core.RabbitAdmin;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.support.converter.JacksonJsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitMQConfig {


    public static final String AUTH_EXCHANGE =
            "auth.events";


    public static final String USER_REGISTERED_ROUTING_KEY =
            "user.registered";

    public static final String EMAIL_VERIFICATION_QUEUE =
            "email.verification.queue";

    @Bean
    public TopicExchange authExchange(){

        return new TopicExchange(
                AUTH_EXCHANGE,
                true,
                false
        );

    }

    @Bean
    public Queue emailVerificationQueue(){

        return new Queue(
                EMAIL_VERIFICATION_QUEUE,
                true
        );

    }

    @Bean
    public AmqpAdmin amqpAdmin(
            ConnectionFactory connectionFactory
    ){

        return new RabbitAdmin(
                connectionFactory
        );

    }

    @PostConstruct
    public void test(){

        System.out.println(
                "RabbitMQ Config Loaded"
        );

    }

    @Bean
    public MessageConverter messageConverter(){

        return new JacksonJsonMessageConverter();

    }


    @Bean
    public RabbitTemplate rabbitTemplate(
            ConnectionFactory connectionFactory,
            MessageConverter messageConverter
    ){

        RabbitTemplate template =
                new RabbitTemplate(connectionFactory);

        template.setMessageConverter(
                messageConverter
        );

        return template;
    }

    @Bean
    public Binding emailVerificationBinding(
            Queue emailVerificationQueue,
            TopicExchange authExchange
    ){

        return BindingBuilder
                .bind(emailVerificationQueue)
                .to(authExchange)
                .with(USER_REGISTERED_ROUTING_KEY);

    }
}