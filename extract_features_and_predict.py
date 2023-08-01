import pandas as pd
import external as ex
import pickle as pk
from tensorflow.keras.models import load_model, Sequential

FEATURES = ['protocol_type', 'service', 'src_IP', 'dest_IP', 'failed_login', 'root_shell', 'su_attempted', 'file_creation',
			'file_access', 'outbound_conn', 'log_accessed', 'packet_len']

MODEL_IS_BUILT = False
data_dir = ''
final_df = []
next_row_index = 0

def read():
	global next_row_index
	dataframe = []
	row = ' '
	while ex.new_rows_count > 0:
		row = ex.packetRow[next_row_index]
		protocol_type = service = ''
		failed_login = root_shell = su_attempted = file_creation = 0
		file_access = outbound_conn = log_accessed = 0
		if 'TCP' in row[3]:
			protocol_type = 'TCP'
		elif 'SSH' in row[3]:
			protocol_type = 'SSH'
		elif 'FTP' in row[3]:
			protocol_type = 'FTP'
		if 'FTP' in row[3]:
			service = 'VSFTPD'
		elif 'SSH' in row[3]:
			service = 'SSHv2'
		elif 'TCP' in row[3]:
			service = 'TCP'
			
		if protocol_type == 'TCP':
			if 'Login incorrect' in row[3]:
				failed_login = 1
			if 'root' in row[3]:
				root_shell = 1
			if 'su' in row[3]:
				su_attempted = 1
			if 'mkdir' in row[3]:
				file_creation = 1
			if 'cat' in row[3] or 'strings' in row[3]:
				file_access = 1
			if '/var/log' in row[3]:
				log_accessed = 1
		elif protocol_type == 'SSH':
			if 'Login Failed' in row[3]:
				failed_login = 1
			if 'root' in row[3]:
				root_shell = 1
			if 'su' in row[3]:
				su_attempted = 1
			if 'mkdir' in row[3]:
				file_creation = 1
			if 'cat' in row[3] or 'strings' in row[3]:
				file_access = 1
			if '/var/log' in row[3]:
				log_accessed = 1
		elif protocol_type == 'FTP':
			if 'Login incorrect' in row[3]:
				failed_login = 1
			if 'USER root' in row[3]:
				root_shell = 1
			if 'USER root' in row[3]:
				su_attempted = 1
			if 'MKD' in row[3]:
				file_creation = 1
			if 'LIST' in row[3] or 'CWD' in row[3]:
				file_access = 1
			if '/var/log' in row[3]:
				log_accessed = 1
		
		dataframe.append([protocol_type, service, row[0], row[1],
			failed_login, root_shell, su_attempted, file_creation, 
			file_access, outbound_conn, log_accessed, row[2]])

		next_row_index += 1
		ex.new_rows_count -= 1

	return pd.DataFrame(dataframe, columns = FEATURES)

def merge(df1, df2):
	return pd.concat([df1, df2], axis = 1)

def read_and_merge(data):
	global final_df
	if type(data) != pd.DataFrame:
		final_df = read()
	else:
		final_df = merge(data, read())

def get_mal_IPs():
	global final_df

	read_and_merge(final_df)
	print(final_df)
	print(ex.packetRow)
	
	model_df = pd.get_dummies(final_df.drop(columns = ['src_IP', 'dest_IP']))
	
	auto_loaded = load_model('trained_autoencoder.h5')
	encoder = Sequential()
	encoder.add(auto_loaded.layers[0])
	reduced_df = encoder.predict(model_df)
	 
	model = pk.load(open("OneClassSVM_auto.pickle", 'rb'))
	pred = pd.Series(model.predict(reduced_df), name = 'Predictions')
	Mal_src_IP = final_df[pred == -1]['src_IP']
	Mal_dest_IP = final_df[pred == -1]['dest_IP']
	Mal_df = pd.concat([Mal_src_IP, Mal_dest_IP], names = ['src_IP', 'dest_IP'], 
                        axis = 1)
	
	print(Mal_df)

# Calling read_and_merge() will read and extract features and merge them to 'final_df'

# Calling get_mal_IPs will return a dataframe containing src and dest IP of Malicious data points in 'final_df'

