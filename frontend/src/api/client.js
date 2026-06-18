import axiosInstance from './axiosInstance.js';

export function apiGet(path) {
  return axiosInstance.get(path).then(r => r.data);
}

export function apiPost(path, body) {
  return axiosInstance.post(path, body).then(r => r.data);
}
