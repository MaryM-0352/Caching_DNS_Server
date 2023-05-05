import pickle
import time


class Record:
    def __init__(self, domain_name, type, data, ttl=0, ip='', server=b''):
        self.record = {
            'domain': domain_name,
            'type': type,
            'valid': [(ip, ttl)],
            'servers': [(server, ttl)],
            'data': data}

    def __getitem__(self, item):
        return self.record[item]


class Cache:
    def __init__(self):
        try:
            with open('cache.pickle', 'rb') as file:
                self.cache = pickle.load(file)
        except FileNotFoundError:
            self.cache = {}

    def __getitem__(self, item):
        return self.cache[item]

    def clean_cache(self):
        to_delete = []
        for key, value in self.cache.items():
            for ip, ttl in value['valid']:
                if ttl < time.time():
                    value['valid'].remove((ip, ttl))
            if len(value['valid']):
                self.cache[key] = value
            else:
                to_delete.append(key)
        for key in to_delete:
            self.cache.pop(key)

    def write(self):
        with open('cache.pickle', 'wb') as file:
            pickle.dump(self.cache, file)

    def put(self, record: Record):
        self.cache[(record['domain'], record['type'])] = \
            {'valid': record['valid'], 'servers': record['servers'], 'data': record['data']}

    def contains(self):
        pass

    def get(self):
        pass

    def print(self):
        for key, value in self.cache.items():
            print(f'key: {key} --- value: {value}')


