import datetime, hmac, hashlib

class TOTP:
    def __init__(self, secret, time_window=30, digits=8, digest=hashlib.sha256):
        self.time_window = time_window
        self.secret = secret
        self.digits = int(digits)
        self.modulo = 10 ** digits
        self.digest = digest
        self.cache = [] # [prev, now, next_]
        self.last_step = -99
    
    def now(self):
        return self.calculate_otp(self.get_time_step())
    
    def vaildate_now(self, d):
        step = self.get_time_step()
        if step == self.last_step + 1:
            self.cache = self.cache[1:] + [self.calculate_otp(step)]
        elif step != self.last_step:
            self.cache = [self.calculate_otp(step - 1),
                          self.calculate_otp(step),
                          self.calculate_otp(step + 1)]
        return any(hmac.compare_digest(d, x) for x in self.cache)
    
    def get_time_step(self):
        dt = datetime.datetime.now(datetime.UTC)
        return int(dt.timestamp()) // self.time_window
    
    def calculate_otp(self, time_sec):
        step = time_sec // self.time_window
        T = step.to_bytes(length=8)
        H = hmac.digest(self.secret, T, self.digest)
        offset = H[-1] & 0xf
        otp = int.from_bytes(H[offset:offset+4]) & 0x7fffffff
        otp %= self.modulo
        return format(otp, f'0{self.digits}d')

