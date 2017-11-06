
import requests

# ==============================================================================
# === LuleboApi
# ==============================================================================

class LuleboApiError(Exception):
	'''Operation in Lulebo Api failed'''





class LuleboLoginApi(object):
	'''
	'''

	# https://portal.lulebo.se/LuleboLogin.asmx/loginPortal

	base_url = 'https://portal.lulebo.se/LuleboLogin.asmx'

	def __init__(self):
		pass

	@staticmethod
	def login(username, password):
		'''
		'''

		url  = LuleboLoginApi.base_url + '/loginPortal'
		data = {
			'UserName'     : username,
			'UserPassword' : password,
			'Zilch'        : '',
			'Embedded'     : 'false'
		}

		r = LuleboApi._post(url, data=data)

		try:
			# Response when login ok
			# "{"d":{"__type":"LuleboLogin+VitecLogin","loginStatus":"ok"}}"
			# Response when login failed
			# "{"d":{"__type":"LuleboLogin+VitecLogin","loginStatus":""}}"
			if not r.json()['d']['loginStatus'] == 'ok':
				raise LuleboApiError()
		except:
			raise LuleboApiError()

		if 'ASP.NET_SessionId' not in r.cookies:
			raise LuleboApiError()

		session_id = r.cookies['ASP.NET_SessionId']
		return session_id

	@staticmethod
	def logout(session_id):
		'''
		'''
		return LuleboSession.endSession(session_id)





class LuleboMvApi(object):
	'''
	'''

	# https://portal.lulebo.se/LuleboMV.asmx/getObjectInfo (query must be called first!?)
	# https://portal.lulebo.se/LuleboMV.asmx/getSiteInfo
	# https://portal.lulebo.se/LuleboMV.asmx/getObjectTimers
	# https://portal.lulebo.se/LuleboMV.asmx/queryObjectStatus

	base_url = 'https://portal.lulebo.se/LuleboMV.asmx'

	def __init__(self):
		pass

	@staticmethod
	def getObjectInfo(self):
		'''
		'''
		url = LuleboSessionApi.base_url + '/getObjectInfo'
		return LuleboApi._post(url, session_id)

	@staticmethod
	def getSiteInfo(self):
		'''
		'''
		url = LuleboSessionApi.base_url + '/getSiteInfo'
		return LuleboApi._post(url, session_id)

	@staticmethod
	def getObjectTimers(self):
		'''
		'''
		url = LuleboSessionApi.base_url + '/getObjectTimers'
		return LuleboApi._post(url, session_id)

	@staticmethod
	def queryObjectStatus(self):
		'''
		'''
		url = LuleboSessionApi.base_url + '/queryObjectStatus'
		return LuleboApi._post(url, session_id)





class LuleboSessionApi(object):
	'''
	'''

	# https://portal.lulebo.se/LuleboSession.asmx/endSession
	# https://portal.lulebo.se/LuleboSession.asmx/getSessionStatus
	
	base_url = 'https://portal.lulebo.se/LuleboSession.asmx'

	def __init__(self):
		pass

	@staticmethod
	def endSession(self):
		url = LuleboSessionApi.base_url + '/endSession'
		return LuleboApi._post(url, session_id)

	@staticmethod
	def getSessionStatus(session_id):
		url = LuleboSessionApi.base_url + '/getSessionStatus'
		return LuleboApi._post(url, session_id)





class LuleboStatusApi(object):
	'''
	'''

	# https://portal.lulebo.se/LuleboStatus.asmx/GetActiveStatusPosts
	
	base_url = 'https://portal.lulebo.se/LuleboStatus.asmx'

	def __init__(self):
		pass

	@staticmethod
	def GetActiveStatusPosts(session_id):
		url = LuleboSessionApi.base_url + '/GetActiveStatusPosts'
		return LuleboApi._post(url, session_id)





class LuleboPassadApi(object):
	'''
	'''

	# https://portal.lulebo.se/LuleboPassad.asmx/getCustomerBookings
	
	base_url = 'https://portal.lulebo.se/LuleboPassad.asmx'

	def __init__(self):
		pass

	@staticmethod
	def getCustomerBookings(self):
		url = LuleboSessionApi.base_url + '/getCustomerBookings'
		return LuleboApi._post(url, session_id)





class LuleboApi(object):
	'''
	'''

	Login   = LuleboLoginApi
	MV      = LuleboMvApi
	Session = LuleboSessionApi
	Status  = LuleboStatusApi
	Passad  = LuleboPassadApi
	

	def __init__(self):
		pass

	# === Private methods
	@staticmethod
	def _post(url, session_id=None, data=None):
		'''
		LuleboApi requires the Content-Type header to be set to json to accept the
		request. The `session_id` is sent as a special cookie.

		This function makes sure that this is handled.
		'''
		kwargs = {}

		headers = {'Content-Type': 'application/json; charset=utf-8'}
		kwargs['headers'] = headers

		if session_id is not None:
			cookies = {'ASP.NET_SessionId': session_id}
			kwargs['cookies'] = cookies

		if data is not None:
			kwargs['json'] = data
		
		return requests.post(url, **kwargs)