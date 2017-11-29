
import multidict
import requests

# ==============================================================================
# === LuleboApi
# ==============================================================================

class LuleboApiError(Exception):
    '''Operation in Lulebo Api failed'''
    def __init__(self, msg):
        self.msg = msg
    def __repr__(self):
        return '<{}: {}>'.format(self.__class__.__name__, self.msg)

class LuleboApiLoginError(LuleboApiError):
    '''Could not authenticate against LuleboAPI'''



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

        print (r.text)

        try:
            # Response when login ok
            # "{"d":{"__type":"LuleboLogin+VitecLogin","loginStatus":"ok"}}"
            # Response when login failed
            # "{"d":{"__type":"LuleboLogin+VitecLogin","loginStatus":""}}"
            if not r.json()['d']['loginStatus'] == 'ok':
                raise LuleboApiLoginError('Authentication error, status not ok')
        except:
            raise LuleboApiLoginError('Authentication error')

        if 'ASP.NET_SessionId' not in r.cookies:
            raise LuleboApiLoginError('Missing cookie')

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

    # Info from: https://portal.lulebo.se/scripts/luleboWebel.js?v=2
    # 
    # https://portal.lulebo.se/LuleboMV.asmx/addObjectBooking
    # https://portal.lulebo.se/LuleboMV.asmx/deleteObjectBooking
    # https://portal.lulebo.se/LuleboMV.asmx/directStartObject
    # https://portal.lulebo.se/LuleboMV.asmx/getObjectInfo (query must be called first!?)
    # https://portal.lulebo.se/LuleboMV.asmx/getSiteInfo
    # https://portal.lulebo.se/LuleboMV.asmx/getObjectTimers
    # https://portal.lulebo.se/LuleboMV.asmx/queryObjectStatus

    base_url = 'https://portal.lulebo.se/LuleboMV.asmx'

    def __init__(self):
        pass

    @staticmethod
    def addObjectBooking(session_id):
        '''
        data: {
            'bookingDay': bookingDay,
            'departureTime': departureTime,
            'reoccuring': reoccuring
        }
        '''
        url = LuleboMvApi.base_url + '/addObjectBooking'
        return LuleboApi._post(url, session_id)

    @staticmethod
    def deleteObjectBooking(session_id):
        '''
        data: {
            'bookingDay': bookingDay,
            'timerId': timerId
        }
        '''
        url = LuleboMvApi.base_url + '/deleteObjectBooking'
        return LuleboApi._post(url, session_id)

    @staticmethod
    def directStartObject(session_id):
        '''
            response object:
                "loginStatus": "zilch" -> user not logged in (session inactive)

            var Runtime = json.d['Runtime'];
            var RCDStatusString = "";

            //RCDStatus – Direktstart och skyddsbrytare OK = 1, Direktstart Ok men utlöst skyddsbrytare = 0, Besked kan ej lämnas för närvarande(Timeout) = -1
            var RCDStatusString = "";
            RCDStatus.toString() == "-1" ? RCDStatusString = "Besked kan ej lämnas. (Timeout eller skyddsbrytare är utlöst)" : "";
            RCDStatus.toString() == "0" ? RCDStatusString = "Skyddsbrytaren är utlöst." : "";

            if (RCDStatus.toString() == "1" && Runtime != "0") {

        '''
        url = LuleboMvApi.base_url + '/directStartObject'
        return LuleboApi._post(url, session_id)

    @staticmethod
    def getObjectInfo(session_id):
        '''
        '''
        url = LuleboMvApi.base_url + '/getObjectInfo'
        return LuleboApi._post(url, session_id)

    @staticmethod
    def getSiteInfo(session_id):
        '''
        '''
        url = LuleboMvApi.base_url + '/getSiteInfo'
        return LuleboApi._post(url, session_id)

    @staticmethod
    def getObjectTimers(session_id):
        '''
        '''
        url = LuleboMvApi.base_url + '/getObjectTimers'
        return LuleboApi._post(url, session_id)

    @staticmethod
    def queryObjectStatus(session_id):
        '''            
            RCDStatus = "-1" => "Timeout";
            RCDStatus = "0"  => "Skyddsbrytare utlöst";
            RCDStatus = "1"  => "Skyddsbrytare ok.";

            IsConnected = "-1" => "Timeout";
            IsConnected = "0" =>  "Sladd _ej_ inkopplad";
            IsConnected = "1" =>  "Sladd inkopplad";
        '''
        url = LuleboMvApi.base_url + '/queryObjectStatus'
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
    def endSession(session_id):
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
        url = LuleboStatusApi.base_url + '/GetActiveStatusPosts'
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
        url = LuleboPassadApi.base_url + '/getCustomerBookings'
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

        headers = {}
        headers['Content-Type'] = 'application/json; charset=utf-8'
        # headers['Accept'] = 'application/json; charset=utf-8'
        kwargs['headers'] = headers

        if session_id is not None:
            cookies = {}
            cookies['ASP.NET_SessionId'] = session_id
            kwargs['cookies'] = cookies

        if data is not None:
            kwargs['json'] = data
        
        return requests.post(url, **kwargs)