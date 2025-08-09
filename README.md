# CSPM-Opensource-Server
 **OpenSource CSPM**은 **공개 SW 개발자 대회** 출전을 위해 개발된 **클라우드 자산 관리 솔루션**입니다.  
 **누구나 쉽게 사용**할 수 있는 **AWS 자산 스캐너**로, **보안 취약점**을 실시간 탐지하여  
 **클라우드 보안 수준**을 높이고 **자산의 안전성**을 강화하는 것을 목표로 합니다.  
본 저장소는 **백엔드** 구현 부분입니다.

---

## 📅 프로젝트 기간
2024.07.25 ~ 2024.08.22 (1개월)

---
## ✨ 담당 역할
본 프로젝트에서 저는 **백엔드 전반의 인증·인가, 회원 관리, 대시보드 API 개발**과 **ERD 설계 및 기획**을 담당했습니다.
- **기획**
  - 요구 분석 및 전체 서비스 기능 기획
  - ERD 설계 및 API 명세 작성

- **인증·인가**
  - Spring Security + JWT 기반 로그인/회원가입 구현
  - Access/Refresh Token 발급·검증 및 토큰 재발급 처리

- **회원 관리**
  - SMTP 이메일 인증 구현
  - AWS Secret Key 검증 로직 개발
  - 비밀번호 재설정 API 제작

- **대시보드 API**
  - 리소스 그룹 관리 API 설계 및 구현
  - 대시보드 데이터 구조 정의 및 응답 최적화


---

## 🛠 기술 스택 (Backend)
<div>
  <img src="https://img.shields.io/badge/Spring%20Boot-6DB33F?style=for-the-badge&logo=Spring%20Boot&logoColor=white"> 
  <img src="https://img.shields.io/badge/Spring%20Security-6DB33F?style=for-the-badge&logo=Spring%20Security&logoColor=white"> 
  <img src="https://img.shields.io/badge/Java-007396?style=for-the-badge&logo=Java&logoColor=white">
  <img src="https://img.shields.io/badge/JPA-59666C?style=for-the-badge&logo=Hibernate&logoColor=white"> 
  <img src="https://img.shields.io/badge/MySQL-4479A1?style=for-the-badge&logo=MySQL&logoColor=white"> 
  <img src="https://img.shields.io/badge/AWS-232F3E?style=for-the-badge&logo=Amazon%20AWS&logoColor=white">
</div>

---


## 📑 기획 자료

| 요구분석 1 | 요구분석 2 |
|:---:|:---:|
| <img width="500" src="https://github.com/user-attachments/assets/95ed16c8-152a-428b-946e-d3b5234c9afb" /> | <img width="500" src="https://github.com/user-attachments/assets/84df59c4-010d-4782-b940-3cb20c46cc19" /> |

**메뉴 구조**  
<img width="800" src="https://github.com/user-attachments/assets/a66c32a6-da2c-4a0d-9097-d52c0fd1fb5c" />

**서비스 플로우**  
<img width="800" src="https://github.com/user-attachments/assets/1e311298-4d5b-4b5c-9e3b-e24aaf8c815b" />


---


###  📸 주요 화면 레이아웃

| 첫 로그인 | 회원가입 |
|:---:|:---:|
| <img width="500" src="https://github.com/user-attachments/assets/eec1cffc-8afb-4ade-a61d-2a37ede0b8d2" /> | <img width="500" src="https://github.com/user-attachments/assets/147408ba-97ce-4ec8-bb79-0ef430e237ce" /> |

| 대시보드 | 설정 |
|:---:|:---:|
| <img width="500" src="https://github.com/user-attachments/assets/68d70ecd-cb8a-40f3-b0ad-96420857ea29" /> | <img width="500" src="https://github.com/user-attachments/assets/5d2f127d-4200-4bfb-be0c-f8b96452ced9" /> |


## 🗂 ERD 설계
<img width="800" src="https://github.com/user-attachments/assets/3325d446-871b-4ab1-97ef-824450b0a8b5" />


## SMTP
**SMTP EmailService**를 구현하여 회원가입 및 비밀번호 재설정 시 이메일 인증 기능을 제공했습니다.

1. 난수 6자리 생성
2. 지정된 이메일로 전송
3. 사용자가 입력한 인증 코드를 API로 전송하여 서버에서 검증
**EmailService 코드**  
<img width="800" src="https://github.com/user-attachments/assets/18daf5a5-e634-4477-9d62-31364db71a8b" />

**실제 이메일 인증 화면**  
<img width="800" src="https://github.com/user-attachments/assets/0bdd0c9d-52f6-4635-9ca8-0a41d7e9ade5" />



## 👨‍💻 팀원
- 정승근 (Backend)
- 박상우
- 이승주
- 이루다
