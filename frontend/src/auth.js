const ACCESS_KEY   = 'openeasd_access';
const REFRESH_KEY  = 'openeasd_refresh';
const IS_ADMIN_KEY = 'openeasd_is_admin';

export const auth = {
  getToken:   () => localStorage.getItem(ACCESS_KEY),
  getRefresh: () => localStorage.getItem(REFRESH_KEY),
  isAdmin:    () => localStorage.getItem(IS_ADMIN_KEY) === 'true',
  setTokens:  (access, refresh) => {
    localStorage.setItem(ACCESS_KEY, access);
    localStorage.setItem(REFRESH_KEY, refresh);
  },
  setAdmin: (isAdmin) => {
    localStorage.setItem(IS_ADMIN_KEY, String(isAdmin));
  },
  clear: () => {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
    localStorage.removeItem(IS_ADMIN_KEY);
  },
  isLoggedIn: () => !!localStorage.getItem(ACCESS_KEY),
};
