package com.commerce.auth.entity;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 23:37
Version 1.0
*/

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 64)
    private String tokenHash;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private LocalDateTime expiredAt;

    @Column(nullable = false)
    private Boolean revoked;

    @Column(length = 255)
    private String deviceInfo;

    @Column(length = 50)
    private String ipAddress;

    private LocalDateTime lastUsedAt;


}