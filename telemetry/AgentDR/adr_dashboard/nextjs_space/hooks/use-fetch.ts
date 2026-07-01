'use client';
import useSWR from 'swr';

const fetcher = (url: string) => fetch(url).then((r) => r.json());

export function useFetch<T = any>(url: string | null, refreshInterval?: number) {
  const { data, error, isLoading, mutate } = useSWR<T>(url, fetcher, {
    refreshInterval: refreshInterval ?? 0,
    revalidateOnFocus: false,
  });
  return { data, error, isLoading, mutate };
}
