package com.elastic.cspm.data.dto;

import com.elastic.cspm.data.entity.DescribeResult;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@Builder
public class ResourceResultData {
//    private LocalDateTime scanTime;
//    private String resourceId;
//    private String scanTarget;
    private String iamName;
    private String groupName;
    private Boolean isAllSuccess;
    private List<DescribeResult> describeEntityList; // 스캔 결과 리스트

//    public static ResourceResultData of(LocalDateTime scanTime, String resourceId, String scanTarget, Boolean isSuccess, List<DescribeResult> describeEntityList) {
    public static ResourceResultData of(String iamName, String groupName, Boolean isSuccess, List<DescribeResult> describeEntityList) {
        return ResourceResultData.builder()
                .iamName(iamName)
                .groupName(groupName)
                .isAllSuccess(isSuccess)
                .describeEntityList(describeEntityList)
                .build();
    }
}

/*
ResourceResultData resourceResultData = ResourceResultData.of(
        LocalDateTime.now(),
        resourceFilterRequestDto.getIam(),
        resourceFilterRequestDto.getGroupName(),
        isAllSuccess,
        describeEntityList
);
 */