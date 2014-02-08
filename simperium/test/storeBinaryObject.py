import argparse
import os
import sys

from simperium import core

class Args(object):
	pass

def get_args():
	parser = argparse.ArgumentParser(description='Upload a file to a Simperium binary bucket.')
	parser.add_argument('-a', '--app', help='Simperium App ID', required=True)
	parser.add_argument('-b', '--bucket', help='Bucket to open', required=True)
	parser.add_argument('-f', '--file', help='Filename for data to upload', type=argparse.FileType('r'), default=sys.stdin)
	parser.add_argument('-i', '--item', help='Item name for upload', default='Unsorted_Files')
	parser.add_argument('-k', '--key', help='Key name for upload', action='store_const', const=None)
	parser.add_argument('-t', '--token', help='Simperium user access token', required=True)

	return parser

def main():
	args = Args()
	parser = get_args()
	parser.parse_args(namespace=args)

	bucket = core.Bucket(args.app, args.token, args.bucket)

	if None == args.key:
		args.key = args.file.name

	print bucket.binary_set(args.item, args.key, args.file.read())

	print bucket.binary_get(args.item, args.key, fetch_url=True)

if __name__ == "__main__":
	main()