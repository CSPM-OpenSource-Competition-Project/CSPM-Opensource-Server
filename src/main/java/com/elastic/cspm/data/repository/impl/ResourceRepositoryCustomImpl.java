package com.elastic.cspm.data.repository.impl;

import com.elastic.cspm.data.dto.QResourceDto;
import com.elastic.cspm.data.repository.ResourceRepositoryCustom;
import com.querydsl.core.types.Projections;
import com.querydsl.jpa.impl.JPAQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static com.elastic.cspm.data.entity.QDescribeResult.describeResult;
import static com.elastic.cspm.data.entity.QMember.member;

@Slf4j
@Repository
public class ResourceRepositoryCustomImpl implements ResourceRepositoryCustom {
    private final JPAQueryFactory queryFactory;

    public ResourceRepositoryCustomImpl(JPAQueryFactory queryFactory) {
        this.queryFactory = queryFactory;
    }

    /**
     * 모든 검색 필터를 적용해서 리스트 반환하는 메서드
     */
    @Override
    @Transactional(readOnly = true)
    public Page<QResourceDto> findResourceList(Pageable pageable) {

        // 필터링 쿼리 + 페이징
        List<QResourceDto> content = createResourceDtoQuery()
                .from(describeResult)
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();
        // stream().toList();

        long total = queryFactory
                .selectFrom(describeResult)
                .fetch().size();

        log.info("Found {}-ResourceResult", content.size());
        log.info("Found {}-ResourceResult", total);
        log.info("Page Size : {}  and PageOffset : {}.", pageable.getPageSize(), pageable.getPageNumber());

        return new PageImpl<>(content, pageable, total);
//        return new PageImpl<>(content);
    }


    /**
     * projection qResourceDto 조회 -> Select 해줌.
     * service를 알면 수정 -> 프론트에서 선택한 것을 그대로 반환해서 리스트에 적어버리면 되지 않을까 생각.
     * 그러면 이 메서드에서 프로젝션으로 생성하지 않아도 되지 않을까?
     */
    @Transactional
    public JPAQuery<QResourceDto> createResourceDtoQuery() {
        return queryFactory.select(
                        Projections.constructor(QResourceDto.class,
                                describeResult.scanTime,
                                describeResult.iam.member.accountId,
                                describeResult.scanTarget,
                                describeResult.resourceId))
                .from(describeResult)
                .leftJoin(describeResult.iam.member, member);
    }
}
