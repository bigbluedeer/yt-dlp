import random
import re

from .common import InfoExtractor
from ..utils import (
    ExtractorError,
    get_element_by_attribute,
    get_element_html_by_class,
    lowercase_escape,
    multipart_encode,
    url_or_none,
)


class ChaturbateIE(InfoExtractor):
    _VALID_URL = r'https?://(?:[^/]+\.)?chaturbate\.com/(?:fullvideo/?\?.*?\bb=)?(?P<id>[^/?&#]+)'
    _TESTS = [{
        'url': 'https://www.chaturbate.com/siswet19/',
        'info_dict': {
            'id': 'siswet19',
            'ext': 'mp4',
            'title': 're:^siswet19 [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}$',
            'age_limit': 18,
            'is_live': True,
        },
        'params': {
            'skip_download': True,
        },
        'skip': 'Room is offline',
    }, {
        'url': 'https://chaturbate.com/fullvideo/?b=caylin',
        'only_matching': True,
    }, {
        'url': 'https://en.chaturbate.com/siswet19/',
        'only_matching': True,
    }]

    _ROOM_OFFLINE = 'Room is currently offline'

    def _perform_roomlogin(self, video_id, referer):
        password = self.get_param('videopassword')
        if password is None:
            raise ExtractorError('Roomlogin requires a video password')

        # there is always 27 dashes in the boundary
        # boundary numbers tend to have between 29 and 30 digits
        # could technically be completely random, but was adjusted to firefox defaults
        boundary = '-' * 27 + ''.join(str(random.randint(0, 9)) for _ in range(random.randint(29, 30)))
        csrf = self._get_cookies('https://chaturbate.com')['csrftoken'].value
        data, content_type = multipart_encode(
            {'password': password, 'csrfmiddlewaretoken': csrf}, boundary=boundary)

        webpage = self._download_webpage(
            'https://chaturbate.com/api/ts/chat/roomloginform/%s/' % video_id,
            video_id, note='Performing roomlogin', data=data,
            headers={'Content-Type': content_type, 'Referer': referer})
        webpage = self._parse_json(webpage, video_id)

        if webpage is None:
            # valid login
            return True

        if 'errors' in webpage:
            self.report_warning('Errors for roomlogin:', video_id)
            for k, v in webpage.get('errors', {}).items():
                self.report_warning('%s: %s' % (k, ', '.join(v)), video_id)

        # sometimes might require a captcha
        if 'extra' in webpage:
            self.report_warning('Extra for roomlogin:', video_id)
            extra = webpage.get('extra', {})
            requires_captcha = extra.pop('requires_captcha', None)

            # output remaining before checking for captcha
            for k, v in extra.items():
                self.report_warning('%s: %s' % (k, str(v)), video_id)

            if requires_captcha:
                # cannot deal with a captcha, probably best to log in manually
                # and use cookies
                self.raise_login_required(
                    'A captcha seems to be required, please log in manually',
                    method='cookies')

        self.raise_login_required('Roomlogin failed')

    def _is_logged_in(self, webpage=None):
        if webpage is None:
            webpage = self._download_webpage('https://chaturbate.com', None)

        # user information header for username is present
        header = get_element_html_by_class('user_information_header_username', webpage)
        if header is not None:
            return True

        # user status is not anonymous
        status = get_element_by_attribute('title', 'Status', webpage)
        if status is not None:
            return 'Anonymous' not in status

        # logged-in user object is not None
        user = self._search_regex(r'logged_in_user:\s*JSON\.parse\(([\'"])(?P<user>.*)\1\),',
                                  webpage, 'logged in user', fatal=False, group='user')
        if user is not None:
            obj = self._parse_json(user, 'logged in user',
                                   transform_source=lowercase_escape, fatal=False)
            # obj is None means logged out
            return obj is not None

        # user information container is not anonymous
        container = self._search_regex(
            r'<div id="user_information_profile_container" class="(?P<class>.*)">',
            webpage, 'user information container', fatal=False, group='class')
        if container is not None:
            # anonymous in container means logged out
            return 'anonymous' not in container

        # is logged in function, not found on room pages
        tf = self._search_regex(
            r'function is_logged_in\(\)\s*{\s*return (?P<tf>true|false);\s*}',
            webpage, 'logged in function', fatal=False, group='tf')
        if tf is not None:
            # fatal because true|false should be valid json
            return self._parse_json(tf, 'logged in function')

        return False

    def _real_extract(self, url):
        video_id = self._match_id(url)

        webpage, urlh = self._download_webpage_handle(
            'https://chaturbate.com/%s/' % video_id, video_id,
            headers=self.geo_verification_headers())

        # redirect to login page
        if re.match(r'https://chaturbate\.com/auth/login.*', urlh.geturl()):
            self.raise_login_required('Login is required for this room',
                                      video_id)

        # redirect to roomlogin page
        if re.match(r'https://chaturbate\.com/roomlogin/%s/?' % video_id,
                    urlh.geturl()):
            # roomlogin only works when logged in
            if not self._is_logged_in(webpage):
                self.raise_login_required('Login is required for this roomlogin',
                                          video_id)

            # this is only required once for the same cookies
            self._perform_roomlogin(video_id, urlh.geturl())

            webpage = self._download_webpage(
                'https://chaturbate.com/%s/' % video_id, video_id,
                headers=self.geo_verification_headers())

        found_m3u8_urls = []

        data = self._parse_json(
            self._search_regex(
                r'initialRoomDossier\s*=\s*(["\'])(?P<value>(?:(?!\1).)+)\1',
                webpage, 'data', default='{}', group='value'),
            video_id, transform_source=lowercase_escape, fatal=False)
        if data:
            m3u8_url = url_or_none(data.get('hls_source'))
            if m3u8_url:
                found_m3u8_urls.append(m3u8_url)

        if not found_m3u8_urls:
            for m in re.finditer(
                    r'(\\u002[27])(?P<url>http.+?\.m3u8.*?)\1', webpage):
                found_m3u8_urls.append(lowercase_escape(m.group('url')))

        if not found_m3u8_urls:
            for m in re.finditer(
                    r'(["\'])(?P<url>http.+?\.m3u8.*?)\1', webpage):
                found_m3u8_urls.append(m.group('url'))

        m3u8_urls = []
        for found_m3u8_url in found_m3u8_urls:
            m3u8_fast_url, m3u8_no_fast_url = found_m3u8_url, found_m3u8_url.replace('_fast', '')
            for m3u8_url in (m3u8_fast_url, m3u8_no_fast_url):
                if m3u8_url not in m3u8_urls:
                    m3u8_urls.append(m3u8_url)

        if not m3u8_urls:
            error = self._search_regex(
                [r'<span[^>]+class=(["\'])desc_span\1[^>]*>(?P<error>[^<]+)</span>',
                 r'<div[^>]+id=(["\'])defchat\1[^>]*>\s*<p><strong>(?P<error>[^<]+)<'],
                webpage, 'error', group='error', default=None)
            if not error:
                if any(p in webpage for p in (
                        self._ROOM_OFFLINE, 'offline_tipping', 'tip_offline')):
                    error = self._ROOM_OFFLINE
            if error:
                raise ExtractorError(error, expected=True)
            raise ExtractorError('Unable to find stream URL')

        formats = []
        for m3u8_url in m3u8_urls:
            for known_id in ('fast', 'slow'):
                if '_%s' % known_id in m3u8_url:
                    m3u8_id = known_id
                    break
            else:
                m3u8_id = None
            formats.extend(self._extract_m3u8_formats(
                m3u8_url, video_id, ext='mp4',
                # ffmpeg skips segments for fast m3u8
                preference=-10 if m3u8_id == 'fast' else None,
                m3u8_id=m3u8_id, fatal=False, live=True))
        self._sort_formats(formats)

        return {
            'id': video_id,
            'title': video_id,
            'thumbnail': 'https://roomimg.stream.highwebmedia.com/ri/%s.jpg' % video_id,
            'age_limit': self._rta_search(webpage),
            'is_live': True,
            'formats': formats,
        }
