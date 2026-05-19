import React from 'react';
import {
  Pagination as ShadcnPagination,
  PaginationContent,
  PaginationItem,
  PaginationNext,
  PaginationPrevious,
} from './ui/pagination.jsx';

export function Pagination({ page, totalPages, onPage }) {
  if (!totalPages || totalPages <= 1) return null;
  return (
    <ShadcnPagination>
      <PaginationContent>
        <PaginationItem>
          <PaginationPrevious
            onClick={() => onPage(page - 1)}
            className={page <= 1 ? 'pointer-events-none opacity-50' : 'cursor-pointer'}
          />
        </PaginationItem>
        <PaginationItem>
          <span className="text-sm text-muted-foreground px-4">
            Page {page} of {totalPages}
          </span>
        </PaginationItem>
        <PaginationItem>
          <PaginationNext
            onClick={() => onPage(page + 1)}
            className={page >= totalPages ? 'pointer-events-none opacity-50' : 'cursor-pointer'}
          />
        </PaginationItem>
      </PaginationContent>
    </ShadcnPagination>
  );
}
