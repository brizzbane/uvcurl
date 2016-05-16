import logging.config

__author__ = 'brizzbane'
base_path = '/home/brizz/dev/net'

def configure_logging(sender=None, **kwargs):
    logging.config.dictConfig(LOGGING_CONFIG)


LOGGING_CONFIG = \
    {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'verbose': {
                'format': '%(levelname)s %(asctime)s %(module)s%(process)d %(thread)d %(message)s'
            },
            'syslog': {
                'format': '%(levelname)s %(asctime)s %(module)s%(process)d %(thread)d %(message)s'
            },
            'simple': {
                'format': '%(name)s %(levelname)s %(message)s'
            },
            'colored': {
                '()': 'colorlog.ColoredFormatter',
                'format': "%(name)s %(log_color)s%(levelname)s %(message)s",
                'log_colors': {
                    'DEBUG': 'purple',
                    'INFO': 'green',
                    'WARNING': 'yellow',
                    'ERROR': 'red',
                    'CRITICAL': 'red,bg_white'},
            }
        },

        'handlers': {
            'console': {
                'level': 'DEBUG',
                'class': 'logging.StreamHandler',
                'formatter': 'colored',
            },

        },

        'loggers': {
            'cURLclient': {
                'handlers': ['console'],
                'level': 'DEBUG',
                'propagate': False,
            },
            'cURLrequest' : {
                'handlers': ['console'],
                'level': 'INFO',
                'propagate': False,
            },
            'concurrent.futures': {
                'handlers': ['console'],
                'level': 'DEBUG',
                'propagate': True,
            },

        }
    }
