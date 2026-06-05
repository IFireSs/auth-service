package com.project.auth_service.service.dto;

import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

public record OffsetBasedPageRequest(int limit, long offset, Sort sort) implements Pageable {
    public static final int DEFAULT_MAX_LIMIT = 200;

    public OffsetBasedPageRequest {
        if (limit < 1) {
            throw new IllegalArgumentException("Limit must be greater than zero");
        }
        if (offset < 0) {
            throw new IllegalArgumentException("Offset must not be negative");
        }
        sort = sort == null ? Sort.unsorted() : sort;
    }

    public static OffsetBasedPageRequest capped(int limit, int offset, Sort sort) {
        return capped(limit, offset, DEFAULT_MAX_LIMIT, sort);
    }

    public static OffsetBasedPageRequest capped(int limit, int offset, int maxLimit, Sort sort) {
        int safeLimit = Math.clamp(limit, 1, maxLimit);
        int safeOffset = Math.max(offset, 0);
        return new OffsetBasedPageRequest(safeLimit, safeOffset, sort);
    }

    @Override
    public int getPageNumber() {
        return Math.toIntExact(offset / limit);
    }

    @Override
    public int getPageSize() {
        return limit;
    }

    @Override
    public long getOffset() {
        return offset;
    }

    @Override
    public Sort getSort() {
        return sort;
    }

    @Override
    public Pageable next() {
        return new OffsetBasedPageRequest(limit, offset + limit, sort);
    }

    @Override
    public Pageable previousOrFirst() {
        return hasPrevious() ? new OffsetBasedPageRequest(limit, Math.max(offset - limit, 0), sort) : first();
    }

    @Override
    public Pageable first() {
        return new OffsetBasedPageRequest(limit, 0, sort);
    }

    @Override
    public Pageable withPage(int pageNumber) {
        return new OffsetBasedPageRequest(limit, (long) pageNumber * limit, sort);
    }

    @Override
    public boolean hasPrevious() {
        return offset > 0;
    }
}
