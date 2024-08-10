package com.elastic.cspm.data.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

@Entity
@Getter
@Setter
@Table(name = "Member")
public class Member implements UserDetails {

    @Id // PK 값 직접 할당 해야 함.
    @Column(name = "email")
    private String email;

    @Column(name="password", nullable = false)
    private String password;

    @CreatedDate
    @Column(name="create_At", nullable = false)
    private LocalDateTime createAt;

    @LastModifiedDate
    @Column(name="update_At", nullable = false)
    private LocalDateTime updateAt;

    @Column(name="role", nullable = false)
    private String role;

    @Column(name="iam_name", nullable = false)
    private String iamName; // IAM 계정 이름

    @Column(name="account_id", nullable = false)
    private String accountId;

    @ManyToOne
    @JoinColumn(name = "resource_group_name")
    private Group group;

    @ManyToOne
    @JoinColumn(name="iam_id")
    private IAM iam;

    /**
     * Security를 위한 UserDetails 구현
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return "";
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }
}
