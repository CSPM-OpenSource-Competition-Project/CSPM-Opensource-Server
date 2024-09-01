package com.elastic.cspm.controller;

import com.elastic.cspm.data.dto.IAMScanGroupResponseDto;
import com.elastic.cspm.data.dto.ResourceFilterRequestDto;
import com.elastic.cspm.data.dto.ResourceResultData;
import com.elastic.cspm.data.dto.ResourceResultResponseDto;
import com.elastic.cspm.data.repository.ResourceRepository;
import com.elastic.cspm.service.IamService;
import com.elastic.cspm.service.RefreshService;
import com.elastic.cspm.service.ResourceService;
import com.elastic.cspm.service.ScanGroupService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/resource")
public class ResourceController {
    private final ResourceService resourceService;
    private final IamService iamService;
    private final ScanGroupService scanGroupService;
    private final RefreshService refreshService;
    private final ResourceRepository resourceRepository;

    /**
     * ScanGroup 선택 API
     */
    @GetMapping("/scangroup")
    public ResponseEntity<List<String>> getScanGroupName(HttpServletRequest request) {
        String email = refreshService.getEmail(request);

        if(email == null || email.isEmpty()){
            return ResponseEntity.badRequest().build();
        }

        try {
            List<String> scanGroups = scanGroupService.getScanGroupName(email);
            return ResponseEntity.ok(scanGroups);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * IAM 선택과 ScanGroup을 같은 API에.
     * 이렇게 한다면 IamSelectDto, ScanGroupSelectDto 삭제.
     */
    @GetMapping("/iam-scanGroup")
    public ResponseEntity<IAMScanGroupResponseDto> getIAMAndScanGroupNames(HttpServletRequest request) {

        String email = refreshService.getEmail(request);

        if(email == null || email.isEmpty()){
            return ResponseEntity.badRequest().build();
        }

        // IAM Nicknames 가져오기
        List<String> iamNicknames = iamService.getIAMNicknames(email);
        log.info("iamNicknames: {}", iamNicknames);

        // ScanGroup Names 가져오기
        List<String> scanGroups = scanGroupService.getScanGroup();
        log.info("scanGroups: {}", scanGroups);


        // 두 리스트를 하나의 DTO에 담기
        IAMScanGroupResponseDto responseDto = new IAMScanGroupResponseDto();
        responseDto.setIamList(iamNicknames);
        responseDto.setScanGroupList(scanGroups);

        return ResponseEntity.ok(responseDto);
    }


    /**
     * ScanGroup에서 boolean으로 1이 되어 있는 자원들을 찾아서 스캔 시작 로직 진행
     * ex) VPC의 경우 vpc, subnet 등이 1로 되어 있음. 이것들만 스캔을 함.
     */
    @PostMapping("/startScan")
    public ResponseEntity<List<ResourceResultData>> getResourcesAndStartScan(@RequestBody ResourceFilterRequestDto resourceFilterRequestDto) throws Exception {
        log.info("스캔 시작");

        if (resourceFilterRequestDto == null) {
            throw new IllegalArgumentException("IAM과 그룹을 선택해야 합니다.");
        }

        // iam과 group 선택하지 않으면 에러가 발생.
        List<ResourceResultData> resourceResultData = resourceService.startDescribe(resourceFilterRequestDto);
        log.info("스캔 끝");

        return ResponseEntity.ok(resourceResultData);
    }

    /**
     * 필터값은 스캔 버튼을 눌르고 끝나면 다른 api가 패치되어서 가져온다.
     * 스캔이 끝나면 프론트가 받은 데이터로 테이블에 올려준다.
     * 페이징해서 describe에 있는 데이터를 프론트에서 보여주면 됨.
     * @RequestParam이므로 "/list?pageIndex=0&pageSize=14" 이런 식으로 전달함.
     */
    @GetMapping("/list")
    public ResponseEntity<ResourceResultResponseDto.ResourceListDto> getResourcesAndList(
            @RequestParam(defaultValue = "0") int pageIndex,
            @RequestParam(defaultValue = "14") int pageSize
    ) throws Exception {

        ResourceResultResponseDto.ResourceListDto resourceListDto = resourceService.scanResultList(pageIndex, pageSize);
        return ResponseEntity.ok(resourceListDto);
    }
}
