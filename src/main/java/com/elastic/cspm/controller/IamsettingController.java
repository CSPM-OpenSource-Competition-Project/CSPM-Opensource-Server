package com.elastic.cspm.controller;

import com.elastic.cspm.data.dto.IamAddDto;
import com.elastic.cspm.data.dto.IamSelectDto;
import com.elastic.cspm.data.dto.InfoResponseDto;
import com.elastic.cspm.service.IamService;
import com.elastic.cspm.service.RefreshService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping(value = "/api/iamsettings")
@RequiredArgsConstructor
public class IamsettingController {
    private final IamService iamService;
    private final RefreshService refreshService;
    @PostMapping("/add")
    public ResponseEntity<Map<String, String>> add(@Valid @RequestBody IamAddDto iamAddDto, HttpServletRequest request){
        String email = refreshService.getEmail(request);

        Boolean isAddIamSuccessful = iamService.add(iamAddDto, email);

        return isAddIamSuccessful ? ResponseEntity.ok(Map.of("result","add sucess")) : ResponseEntity.badRequest().body(Map.of("result","add fail"));
    }


    @GetMapping("/validation/iam")
    public ResponseEntity<InfoResponseDto> addIamValidation(@RequestParam String accessKey, @RequestParam String secretKey, @RequestParam String region) {
        if (accessKey == null || secretKey == null || region == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build(); // 400 Bad Request
        }

        InfoResponseDto infoResponseDto = iamService.validationIam(accessKey, secretKey, region);

        if (infoResponseDto == null) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build(); // 500 Internal Server Error
        }
        if (infoResponseDto.getStatus() == 0) {
            return ResponseEntity.ok(infoResponseDto); // 200 OK
        } else if (infoResponseDto.getStatus() == 1) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build(); // 403 Forbidden 인증은 성공 권한 문제
        }else if (infoResponseDto.getStatus() == 2){
            return ResponseEntity.status(HttpStatus.GONE).build(); // 410 Gone
        }else {
            return ResponseEntity.status(HttpStatus.CONFLICT).build(); // 409 Conflict 중복
        }
    }
    @DeleteMapping
    public ResponseEntity<Void> deleteIam(@RequestBody List<IamSelectDto> iamSelectDtoList){
        return iamService.iamDelete(iamSelectDtoList);
    }

}
