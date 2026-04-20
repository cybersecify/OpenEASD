const ACCESS_KEY  = 'openeasd_access';
const REFRESH_KEY = 'openeasd_refresh';

export const auth = {
  getToken:   () => localStorage.getItem(ACCESS_KEY),
  getRefresh: () => localStorage.getItem(REFRESH_KEY),
  setTokens:  (access, refresh) => {
    localStorage.setItem(ACCESS_KEY, access);
    localStorage.setItem(REFRESH_KEY, refresh);
  },
  clear: () => {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
  },
  isLoggedIn: () => !!localStorage.getItem(ACCESS_KEY),
};
