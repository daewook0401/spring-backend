# 프로젝트 개요

* **목적**: Spring Boot 기반의 백엔드 프로젝트로, 대부분의 웹서비스에서 공통으로 쓰이는 기능(인증/인가, 유저/권한, 파일, 페이지네이션/검색, 공통 응답, 에러코드, 로깅/감사, 알림, 코드/사전 등)을 **RESTful 규칙**에 맞춰 제공하는 범용 템플릿 구축.
* **스택**: Spring Boot 3.x, Java 21 amazon coretto, Oracle Database (ATP/On-Prem), MyBatis 3.x, Gradle, Flyway, Spring Security, JWT, Bean Validation, OpenAPI(Swagger), Testcontainers(선택), Docker(선택).

---

## RESTful 설계 원칙 (프로젝트 전역 규칙)

1. **리소스 명명**: 복수형, 소문자, 하이픈 미사용 → `snake_case`·`camelCase` 대신 **kebab-case 금지**, **스네이크 금지**, 권장: `/users`, `/roles`, `/files` 등.
2. **행위는 HTTP 메서드로**: `GET`(조회), `POST`(생성), `PUT`(전체수정), `PATCH`(부분수정), `DELETE`(삭제).
3. **상태코드 일관화**: 200/201/204/400/401/403/404/409/422/429/500.
4. **페이지네이션 표준**: `GET /{resource}?page=1&size=20&sort=field,asc&query=...`.
5. **표준 응답 래퍼**: `data`, `meta`, `error` 3영역 고정.
6. **버저닝**: URL 버전 권장: `/api/v1/...` (중장기 `/v2` 전환 용이).
7. **Idempotency**: 재시도 가능한 API(특히 POST-결제/업로드 등)에 `Idempotency-Key` 헤더 선택 지원.

---

## 모듈 구성 (Common Toolkit)

* **auth**: JWT 발급/갱신, 리프레시 토큰 보관, 권한(Role/Permission).
* **users**: 회원/프로필, 비밀번호 변경, 이메일/닉네임 중복체크.
* **files**: 파일 업로드/다운로드(로컬 혹은 Object Storage), 썸네일, MIME 검증.
* **codes**: 공통코드(코드/코드그룹), 지역/카테고리 등 사전 데이터 API.
* **search**: 공통 페이지네이션·정렬·조건 검색 파서.
* **notify**(선택): 이메일/웹훅/푸시 알림 어댑터 구조.
* **audit**: 요청 추적(traceId), 변경 이력(작성/수정자, IP/UA), DB Audit 컬럼 자동화.
* **obs**(선택): 모니터링(Micrometer, Prometheus), 헬스체크 `/actuator/health`.

---

## 패키지 구조 (예시)

```
com.example.app
 ├─ api
 │   ├─ v1
 │   │   ├─ auth
 │   │   ├─ users
 │   │   ├─ files
 │   │   └─ codes
 │   └─ advice (GlobalExceptionHandler)
 ├─ core
 │   ├─ config (Security, MyBatis, Jackson, OpenAPI, CORS)
 │   ├─ domain (엔티티/레코드, VO)
 │   ├─ mapper (MyBatis Mapper)
 │   ├─ service
 │   ├─ util (Crypto, Date, Idempotency, Pagination)
 │   └─ support (AOP, Auditing)
 ├─ infra
 │   ├─ storage (File, ObjectStorage adapter)
 │   └─ mail / sms / webhook
 └─ common
     ├─ dto (Request/Response, Page, Error)
     └─ enums (ErrorCode, Role, Provider)
```

---

### 패키지 의존성 규칙(상향식 금지, 하향식 허용)

아래 방향만 허용합니다. 역참조는 금지해 구조를 견고하게 유지합니다.

```
api  ─────▶  core  ─────▶  common
  │             │
  └────────────▶│
infra ─────────▶│
```

* **api → core, common**: 컨트롤러는 서비스/DTO만 의존. 인프라 빈을 직접 주입 금지.
* **core → common**: 도메인/서비스는 공용 DTO·유틸만 사용. infra로 역참조 금지.
* **infra → core, common**: 어댑터 구현체는 core에서 정의한 인터페이스(포트)에 의존.

> 핵심 아이디어: **core는 규칙(포트)을, infra는 구현(어댑터)을, api는 입·출력을 담당**합니다.

---

### 각 레이어 역할과 포함/금지 항목

#### 1) `api`

* **역할**: HTTP 엔드포인트, 요청 검증, 응답 매핑, 예외 → 표준 에러로 변환.
* **포함**: `@RestController`, request/response DTO, `@ControllerAdvice`, 인증 진입점.
* **금지**: 비즈니스 로직, DB 접근 코드(MyBatis/Repository), 외부 연동 클라이언트 직접 사용.
* **버저닝**: `api.v1` 아래에 리소스 컨트롤러. 이후 변경은 `api.v2`로 **병렬 유지** 후 점진적 폐기.
* **예시**: `api.v1.users.UserController`, `api.advice.GlobalExceptionHandler`.

#### 2) `core`

* **역할**: **도메인 규칙과 유즈케이스**. 트랜잭션 경계(`@Transactional`)가 주로 위치.
* **포함**: `domain`(Entity/VO/Record), `service`(비즈니스 유즈케이스), `mapper` 또는 `port`(인터페이스), 공통 `util`, AOP, 설정.
* **선택 설계**:

  * **포트/어댑터 방식(권장)**: `core.port.out.UserRepository`(인터페이스)만 두고,
    구현은 `infra.persistence.mybatis.UserRepositoryImpl`에서 MyBatis로 구현.
  * **단순 방식**: `core.mapper`에 MyBatis Mapper 인터페이스 두고, XML은 `resources/mapper`에 배치(현재 예시).
* **금지**: 외부 라이브러리 종속 로직을 직접 호출(메일 전송, S3 등). 반드시 인터페이스로 추상화.
* **예시**: `core.service.UserService`, `core.domain.User`, `core.port.out.FileStoragePort`.

#### 3) `infra`

* **역할**: 외부 세계와의 연결부(영속성, 메시징, 파일/오브젝트 스토리지, 메일/SMS, 서드파티 API).
* **포함**: 어댑터 구현체(예: MyBatis/JPA 구현, S3/GCS 클라이언트 래퍼, MailSender), 설정 바인딩.
* **금지**: 컨트롤러, 도메인 규칙 구현, API DTO 의존.
* **예시**: `infra.persistence.mybatis.UserRepositoryImpl`, `infra.storage.LocalFileStorage`, `infra.notify.EmailSenderImpl`.

#### 4) `common`

* **역할**: 전 계층에서 재사용되는 **완전 중립 모듈**.
* **포함**: 응답 래퍼 DTO, 에러/예외, 페이지네이션 DTO, enum, 상수, 작은 유틸.
* **금지**: 비즈니스 규칙, 데이터 접근 코드.
* **예시**: `common.dto.ApiResponse`, `common.enums.ErrorCode`, `common.dto.PageResponse`.

---

### `api.v1`를 따로 묶는 이유와 운용 패턴

* **명확한 변형 추적**: v1의 계약(필드·상태코드·에러 스펙)을 고정하고, 큰 변경은 v2로 추가.
* **병렬 운영**: `api.v1.*`와 `api.v2.*`를 **동시에 구동**해 점진적 마이그레이션.
* **Deprecation 전략**: v2 출시 → v1에 `@Deprecated`·응답 헤더 `Deprecation`/`Sunset`(날짜) 노출 → 문서에 마이그레이션 가이드.

---

### 경계(입·출력)에서의 변환 규칙

* **Controller**: `RequestDTO → 도메인/커맨드` 변환, `결과 → ResponseDTO` 매핑.
* **Service**: 도메인 규칙·트랜잭션·권한 체크. `Port/Repository` 호출.
* **Infra Adapter**: `Port` 구현. DB/외부 API 모델 ↔ 도메인 모델 매핑 유지.

---

### 트랜잭션 & 예외

* **트랜잭션 위치**: `core.service`(유즈케이스 메서드 단위). 읽기 전용은 `@Transactional(readOnly=true)`.
* **예외 흐름**: infra 예외 → core 커스텀 예외로 래핑 → api의 `GlobalExceptionHandler`에서 표준 에러로 변환.

---

### 테스트 전략(계층별)

* **api**: `@WebMvcTest`로 컨트롤러 슬라이스, 요청/응답 스펙 검증.
* **core**: 순수 단위 테스트(도메인/서비스), 트랜잭션 규칙·권한·검증 로직 집중.
* **infra**: Testcontainers(Oracle XE)로 매퍼/리포지토리 통합 테스트.

---

### 냄새 체크리스트(Do/Don't)

* **Do**: 컨트롤러는 100~150줄 내외, 서비스는 유즈케이스 중심(메소드명은 동사+목적).
* **Don't**: 컨트롤러에서 `mapper.select*` 호출, 서비스에서 `RestTemplate/S3Client` 직접 호출(Port 통해 호출), core에서 api DTO 직접 의존.

---

### 작은 예시(포트/어댑터)

```java
// core.port.out
public interface FileStoragePort { String put(String path, byte[] bytes); void delete(String path); }

// core.service
@RequiredArgsConstructor
public class UploadAvatarService {
  private final FileStoragePort storage; // Port에만 의존
  @Transactional
  public String upload(Long userId, byte[] image){ /* 검증·권한 확인 */ return storage.put("avatars/"+userId, image); }
}

// infra.storage (어댑터)
@Component
@RequiredArgsConstructor
public class LocalFileStorage implements FileStoragePort { /* 실제 파일 저장 구현 */ }
```

com.example.app
├─ api
│   ├─ v1
│   │   ├─ auth
│   │   ├─ users
│   │   ├─ files
│   │   └─ codes
│   └─ advice (GlobalExceptionHandler)
├─ core
│   ├─ config (Security, MyBatis, Jackson, OpenAPI, CORS)
│   ├─ domain (엔티티/레코드, VO)
│   ├─ mapper (MyBatis Mapper)
│   ├─ service
│   ├─ util (Crypto, Date, Idempotency, Pagination)
│   └─ support (AOP, Auditing)
├─ infra
│   ├─ storage (File, ObjectStorage adapter)
│   └─ mail / sms / webhook
└─ common
├─ dto (Request/Response, Page, Error)
└─ enums (ErrorCode, Role, Provider)

````

---

## Gradle 의존성 (build.gradle.kts 예시)

```kotlin
dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("io.jsonwebtoken:jjwt-api:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.6")

    implementation("org.mybatis.spring.boot:mybatis-spring-boot-starter:3.0.3")
    implementation("com.oracle.database.jdbc:ojdbc11:23.4.0.24.05")

    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.6.0")
    implementation("org.springframework.boot:spring-boot-starter-actuator")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.testcontainers:junit-jupiter")
    testImplementation("org.testcontainers:oracle-xe:1.20.2")
}
````

---

## 설정 템플릿 (application.yml)

```yaml
server:
  port: 8080
spring:
  datasource:
    url: jdbc:oracle:thin:@YOUR_DB_ALIAS?TNS_ADMIN=/app/wallet
    username: APP_USER
    password: ${DB_PASSWORD}
    driver-class-name: oracle.jdbc.OracleDriver
  jackson:
    serialization:
      WRITE_DATES_AS_TIMESTAMPS: false
  mvc:
    format:
      date-time: iso
mybatis:
  mapper-locations: classpath:/mapper/**/*.xml
  type-aliases-package: com.example.app.core.domain
  configuration:
    map-underscore-to-camel-case: true
cors:
  allowed-origins: "https://your-domain, http://localhost:5173"
  allowed-methods: "GET,POST,PUT,PATCH,DELETE,OPTIONS"
  allowed-headers: "*"
  allow-credentials: true
jwt:
  issuer: example.com
  access-token-ttl-minutes: 30
  refresh-token-ttl-days: 14
```

---

## 공통 응답 규격

```json
{
  "data": {},
  "meta": {
    "timestamp": "2025-10-14T10:00:00+09:00",
    "traceId": "a1b2c3",
    "page": {
      "number": 1,
      "size": 20,
      "totalElements": 123,
      "totalPages": 7
    }
  },
  "error": null
}
```

### 자바 DTO 예시

```java
public record ApiResponse<T>(T data, Meta meta, ApiError error) {
    public static <T> ApiResponse<T> ok(T data, Meta meta){
        return new ApiResponse<>(data, meta, null);
    }
    public static ApiResponse<Void> error(ApiError err, Meta meta){
        return new ApiResponse<>(null, meta, err);
    }
}
```

### 에러 코드 컨벤션

* 포맷: `Sxxx`(성공 보조), `E400x`(클라이언트), `E500x`(서버) 등.

```java
public enum ErrorCode {
    E4000_INVALID_REQUEST(400, "잘못된 요청"),
    E4010_UNAUTHORIZED(401, "인증 필요"),
    E4030_FORBIDDEN(403, "권한 없음"),
    E4040_NOT_FOUND(404, "리소스 없음"),
    E4090_CONFLICT(409, "충돌"),
    E4220_UNPROCESSABLE(422, "처리 불가"),
    E4290_TOO_MANY(429, "요청 과다"),
    E5000_SERVER_ERROR(500, "서버 오류");
    public final int status; public final String message;
    ErrorCode(int s, String m){ this.status=s; this.message=m; }
}
```

### 예외 처리기

```java
@RestControllerAdvice
public class GlobalExceptionHandler {
  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ApiResponse<Void>> handleValidation(MethodArgumentNotValidException ex) {
    var meta = Meta.now();
    var err = new ApiError(ErrorCode.E4000_INVALID_REQUEST, ex.getMessage());
    return ResponseEntity.badRequest().body(ApiResponse.error(err, meta));
  }
  // NotFound, Unauthorized 등 추가
}
```

---

## 페이지네이션 & 검색 규약

* 쿼리 파라미터: `page(1..n)`, `size(1..100)`, `sort=field,asc|desc`(여러개 허용), `query`(fulltext 유사), `filters=key:value,key2:value2`.
* 응답 `meta.page` 영역으로 페이징 정보 제공.
* MyBatis에서 **동적 SQL**로 정렬/검색 조합 처리.

### 공통 Page DTO

```java
public record PageRequest(int page, int size, List<Sort> sort) {}
public record PageResponse<T>(List<T> content, long totalElements, int totalPages) {}
public record Sort(String field, String direction) {}
```

---

## 보안/인증 (JWT + Spring Security)

* **흐름**: `POST /api/v1/auth/login` → Access(30m) + Refresh(14d) 발급 → `Authorization: Bearer <access>` 사용 → 만료 시 `POST /api/v1/auth/refresh`.
* **리프레시 토큰 저장**: Oracle `TB_TOKEN` 테이블(블랙리스트/만료일 포함) + 인덱스.
* **권한**: `ROLE_USER`, `ROLE_ADMIN` 등 + `@PreAuthorize` 스코프 기반.

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
  @Bean SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf.disable())
       .authorizeHttpRequests(reg -> reg
         .requestMatchers("/api/v1/auth/**", "/v3/api-docs/**", "/swagger-ui/**").permitAll()
         .anyRequest().authenticated())
       .addFilterBefore(jwtFilter(), UsernamePasswordAuthenticationFilter.class);
    return http.build();
  }
}
```

---

## Oracle DDL (핵심 테이블 예시)

```sql
-- 회원
CREATE TABLE TB_USER (
  USER_ID        NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  EMAIL          VARCHAR2(255) UNIQUE NOT NULL,
  PASSWORD_HASH  VARCHAR2(255) NOT NULL,
  NICKNAME       VARCHAR2(50)  UNIQUE NOT NULL,
  ROLE           VARCHAR2(30)  DEFAULT 'ROLE_USER' NOT NULL,
  CREATED_AT     TIMESTAMP DEFAULT SYSTIMESTAMP,
  UPDATED_AT     TIMESTAMP
);
CREATE INDEX IDX_USER_EMAIL ON TB_USER(EMAIL);

-- 토큰 보관
CREATE TABLE TB_TOKEN (
  TOKEN_ID     NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  USER_ID      NUMBER NOT NULL,
  TOKEN_TYPE   VARCHAR2(20) NOT NULL, -- ACCESS/REFRESH
  TOKEN_VALUE  VARCHAR2(1024) NOT NULL,
  EXPIRES_AT   TIMESTAMP NOT NULL,
  REVOKED      CHAR(1) DEFAULT 'N' CHECK (REVOKED IN ('Y','N')),
  CREATED_AT   TIMESTAMP DEFAULT SYSTIMESTAMP,
  CONSTRAINT FK_TOKEN_USER FOREIGN KEY (USER_ID) REFERENCES TB_USER(USER_ID)
);
CREATE INDEX IDX_TOKEN_USER_EXPIRE ON TB_TOKEN(USER_ID, EXPIRES_AT);

-- 공통코드
CREATE TABLE TB_CODE_GROUP (
  GROUP_ID   NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  GROUP_KEY  VARCHAR2(64) UNIQUE NOT NULL,
  NAME       VARCHAR2(128) NOT NULL
);
CREATE TABLE TB_CODE (
  CODE_ID    NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  GROUP_ID   NUMBER NOT NULL,
  CODE_KEY   VARCHAR2(64) NOT NULL,
  NAME       VARCHAR2(128) NOT NULL,
  ORD        NUMBER DEFAULT 0,
  USE_YN     CHAR(1) DEFAULT 'Y',
  CONSTRAINT FK_CODE_GROUP FOREIGN KEY (GROUP_ID) REFERENCES TB_CODE_GROUP(GROUP_ID)
);
CREATE UNIQUE INDEX UQ_CODE_GROUP_KEY ON TB_CODE(GROUP_ID, CODE_KEY);
```

---

## MyBatis 매퍼 패턴 (예시)

**Mapper 인터페이스**

```java
@Mapper
public interface UserMapper {
  Optional<User> findByEmail(String email);
  int insert(User user);
  int update(User user);
  int deleteById(Long userId);
  List<User> search(@Param("offset") int offset, @Param("limit") int limit,
                    @Param("sort") String sort, @Param("query") String query);
  long count(@Param("query") String query);
}
```

**XML (동적 정렬/검색)**

```xml
<select id="search" resultType="com.example.app.core.domain.User">
  SELECT * FROM TB_USER
  <where>
    <if test="query != null and query != ''">
      (LOWER(EMAIL) LIKE CONCAT('%', LOWER(#{query}), '%') OR LOWER(NICKNAME) LIKE CONCAT('%', LOWER(#{query}), '%'))
    </if>
  </where>
  <choose>
    <when test="sort != null and sort != ''">ORDER BY ${sort}</when>
    <otherwise>ORDER BY CREATED_AT DESC</otherwise>
  </choose>
  OFFSET #{offset} ROWS FETCH NEXT #{limit} ROWS ONLY
</select>
```

---

## 컨트롤러 예시 (Users)

```java
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {
  private final UserService userService;

  @GetMapping
  public ApiResponse<PageResponse<UserSummary>> list(@Valid PageQuery q) {
    var page = userService.search(q);
    return ApiResponse.ok(page, Meta.nowWithPage(page));
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  public ApiResponse<UserDetail> create(@Valid @RequestBody UserCreate req){
    return ApiResponse.ok(userService.create(req), Meta.now());
  }

  @GetMapping("/{id}")
  public ApiResponse<UserDetail> get(@PathVariable Long id){
    return ApiResponse.ok(userService.get(id), Meta.now());
  }

  @PatchMapping("/{id}")
  public ApiResponse<UserDetail> update(@PathVariable Long id, @Valid @RequestBody UserUpdate req){
    return ApiResponse.ok(userService.update(id, req), Meta.now());
  }

  @DeleteMapping("/{id}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void delete(@PathVariable Long id){
    userService.delete(id);
  }
}
```

---

## OpenAPI 문서화 규칙

* `springdoc-openapi` 자동 스캔 + `@Operation`, `@Schema`로 모델/예외 명세화.
* 보안 스킴: HTTP Bearer (JWT) 명시 → Swagger UI에서 토큰 입력 가능.
* 빌드 시 YAML 내보내기: `mvn/gradle` 태스크로 `/openapi.yaml` 산출.

---

## 품질/운영 체크리스트

* **테스트**: 단위/통합 테스트 + Testcontainers(Oracle XE)로 Mapper/Repo 검증.
* **마이그레이션**: Flyway `V1__init.sql`로 스키마 버전관리.
* **로깅**: 요청ID(traceId) MDC 주입, 감사필드 자동화(AOP).
* **보안**: 입력 검증(Bean Validation), 파일 업로드 MIME/크기 제한, CORS 최소허용, 헤더 보안.
* **성능**: 인덱스/실행계획 점검, N+1 예방, 페이징 커버링 인덱스.
* **운영**: Actuator health/readiness, 장애코드 표준화, RateLimit(필요 시 Bucket4j).

---

## 초기 마일스톤 제안 (2주 Sprint 기준)

1. **V1 스켈레톤**: 프로젝트 구조/의존성, 공통 응답/에러, GlobalException, OpenAPI, Security 기본, Health 체크.
2. **Auth/User 기능**: 로그인/회원가입/리프레시/권한, TB_USER·TB_TOKEN, MyBatis 매퍼/테스트.
3. **Codes/Files 공통**: 공통코드 CRUD, 파일 업로드(로컬 디스크), 페이지네이션 공통 모듈.
4. **운영화**: Flyway 마이그레이션, 로깅/감사, Swagger 배포, 도커라이징(선택).

---

## 다음 액션

* 본 문서 기반으로 초기 리포지토리 생성(GitHub 템플릿) → 기본 코드/설정 반영.
* 실제 도메인(예: 게시판, 포인트, 알림 등) 추가 요구사항을 각 모듈에 적층.
* 필요 시 Oracle Wallet 셋업/환경변수(.env, K8s Secret) 가이드 별도 작성.
