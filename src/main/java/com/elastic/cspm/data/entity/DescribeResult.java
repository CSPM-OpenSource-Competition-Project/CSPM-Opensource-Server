package com.elastic.cspm.data.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import software.amazon.awssdk.services.ec2.model.VolumeAttachment;
import software.amazon.awssdk.services.ec2.model.VolumeState;

import java.time.LocalDateTime;
import java.util.List;

import static jakarta.persistence.FetchType.LAZY;

@Entity
@Getter
@Setter
@Table(name = "DescribeResult")
public class DescribeResult {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "describe_id")
    private Long id;

    @Column(name = "scan_time", nullable = true)
    private LocalDateTime scanTime;

    @Column(name = "resource_id", nullable = false)
    private String resourceId;

    @Column(name = "scan_target", nullable = false)
    private String scanTarget; // resource로 스캔 대상

    @Column(name = "group_name", nullable = false)
    private String groupName;

    @ManyToOne(fetch = LAZY)
    @JoinColumn(name = "iam_id")
    private IAM iam;
}
