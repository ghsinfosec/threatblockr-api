import globals
import requests


globals.init()


def setup_args(subparser):
    report_parser = subparser.add_parser('report', help='Get report data for the specified report and period')
    report_parser.add_argument('-r', '--report', dest='report_type', choices=['reasons', 'categories', 'countries', 'asns'], help='Report type - e.g. reasons, categories, countries, asns')


# function to run the specified report
def run_report(report):
    
    # remove the Content-Type header
    globals.headers.pop('Content-Type')

    # send a GET request for the report type endpoint
    response = requests.get(f'{globals.base_url}/reports/{report}?preset=last_week', headers=globals.headers).text
    print(response)


def run(args):
    reports = {
            'reasons': 'totals',
            'categories': 'totals',
            'asns': 'threats/asns/totals',
            'countries': 'threats/countries/totals'
            }

    if args.report_type in reports.keys():
        run_report(reports[args.report_type])


