from django.core.management.base import BaseCommand
from nvd.utils import get_gzipped_json, create_json_name, reflect_collected_data
from gzip import decompress
from json import loads, dump
import os, re, datetime, logging
from requests import get

""" ログ取得設定 """
#初期パラメータ設定
logdir = r"/Users/masuda/boring/project/csirt/nvd/log/"
#現在時刻の取得
date_name = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
#ファイル名の生成
file_name = logdir + "\\" + date_name +  "_" + "UPDATE_VULN_DATA.log"
logging.basicConfig(filename=file_name,level=logging.DEBUG,format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

class Command(BaseCommand):
    """ カスタムコマンド定義 """
    def handle(self, *args, **options):

        logging.info('[正常]脆弱性情報収集処理を開始します。')

        base_url = "https://nvd.nist.gov/feeds/json/cve/1.0/"
        dt_now =datetime.datetime.now()
        download_json_gzs = ["nvdcve-1.0-{year}.json.gz".format(year=str(dt_now.year)), "nvdcve-1.0-recent.json.gz", "nvdcve-1.0-modified.json.gz"]

        for download_json_gz in download_json_gzs:
            full_url = base_url + download_json_gz
            json_file_name= create_json_name(full_url)

            with open(json_file_name, mode='w') as f:
                dump(get_gzipped_json(full_url), f)
            logging.info('[正常]脆弱性情報収集処理が正常終了しました。')
            logging.info('[正常]脆弱性情報{file_name}保存処理を開始します。'.format(file_name=str(json_file_name)))
            reflect_collected_data(json_file_name)
            logging.info('[正常]脆弱性情報{file_name}保存処理が正常終了しました。'.format(file_name=str(json_file_name)))

    
    

