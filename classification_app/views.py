import os
from traffic_classification.settings import UPLOAD_PATH, MODEL_PATH
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.contrib import messages
from django.http import HttpResponse

from scapy.all import *
from sklearn import preprocessing
import numpy as np
import binascii
from tensorflow.keras.models import load_model


# Create your views here.


# 加载上传文件,并进行预处理
def preproccess_traffic(file_name):
    pass


# 通过scapy取得流量的相关信息
def get_traffic_info(file_name):
    file_path = os.path.join(UPLOAD_PATH, file_name)
    pcaps = rdpcap(file_path)
    for data in pcaps:
        if 'UDP' in data:
            s = repr(data)
            if s:
                src_ip = data['IP'].src
                src_port = data['UDP'].sport
                dst_ip = data['IP'].dst
                dst_port = data['UDP'].dport
            protocol = 'UDP'
            break
        if 'TCP' in data:
            s = repr(data)
            if s:
                src_ip = data['IP'].src
                src_port = data['TCP'].sport
                dst_ip = data['IP'].dst
                dst_port = data['TCP'].dport
            protocol = 'TCP'
            break
    return src_ip, src_port, dst_ip, dst_port, protocol


# 模型预测流量类型
def encrypted_traffic_classify(file_name):
    # 将pcap文件转换成矩阵
    file_path = os.path.join(UPLOAD_PATH, file_name)
    with open(file_path, 'rb') as f:
        content = f.read()
    hexst = binascii.hexlify(content)
    fh = np.array([int(hexst[i:i + 2], 16) for i in range(0, len(hexst), 2)])[:784]
    rn = len(fh) // 28
    fh = np.reshape(fh[:rn * 28], (-1, 28))
    fh = np.uint8(fh)

    # 归一化矩阵数值
    fh = fh.astype(float)
    minmax = preprocessing.MinMaxScaler()
    normalize_fh = minmax.fit_transform(fh)

    input_pcap = normalize_fh.reshape((1, 28, 28))

    # 加载模型并预测结果
    model_path = os.path.join(MODEL_PATH, 'ISCX_model.h5')
    model = load_model(model_path)
    traffic_class = model.predict_classes(input_pcap)[0]

    result = ''
    #
    # if traffic_class == 0:
    #     result = 'chat'
    # elif traffic_class == 1:
    #     result = 'email'
    # elif traffic_class == 2:
    #     result = 'file'
    # elif traffic_class == 3:
    #     result = 'P2P'
    # elif traffic_class == 4:
    #     result = 'streaming'
    # elif traffic_class == 5:
    #     result = 'voip'
    # elif traffic_class == 6:
    #     result = 'VPN_chat'
    # elif traffic_class == 7:
    #     result = 'VPN_email'
    # elif traffic_class == 8:
    #     result = 'VPN_file'
    # elif traffic_class == 9:
    #     result = 'VPN_P2P'
    # elif traffic_class == 10:
    #     result = 'VPN_streaming'
    # elif traffic_class == 11:
    #     result = 'VPN_voip'

    return result


def ids_traffic_classify(file_name):
    # 将pcap文件转换成矩阵
    file_path = os.path.join(UPLOAD_PATH, file_name)
    with open(file_path, 'rb') as f:
        content = f.read()
    hexst = binascii.hexlify(content)
    fh = np.array([int(hexst[i:i + 2], 16) for i in range(0, len(hexst), 2)])[:784]
    rn = len(fh) // 28
    fh = np.reshape(fh[:rn * 28], (-1, 28))
    fh = np.uint8(fh)

    # 归一化矩阵数值
    fh = fh.astype(float)
    minmax = preprocessing.MinMaxScalar()
    normalize_fh = minmax.fit_transform(fh)

    input_pcap = normalize_fh.reshape((1, 28, 28))

    # 加载模型并预测结果
    model = load_model(os.path.join(MODEL_PATH, 'ids_model.h5'))
    traffic_class = model.predict_classes(input_pcap)[0]
    result = ''
    if traffic_class >= 10:
        result = '恶意流量'
    else:
        result = '正常流量'

    return result


@csrf_exempt
def index(request):
    # 加入文件上传功能并将文件保存至本地文件夹，同时进行文件预处理工作用于前端流量展示和后端流量分类工作，并将预处理后的文件保存至数据库
    if request.method == 'POST':

        myFile = request.FILES.get("myfile", None)  # 获取上传文件，如果没有，则默认为None
        if not myFile:
            messages.error(request, "文件上传失败")
            return render(request, 'classification_app/index.html')

        destination = open(os.path.join(UPLOAD_PATH, myFile.name), 'wb+')
        for chunk in myFile.chunks():
            destination.write(chunk)
        destination.close()

        src_ip, src_port, dst_ip, dst_port, protocol = get_traffic_info(myFile.name)
        classify_result = encrypted_traffic_classify(myFile.name)
        # traffic_type = myFile.name.split('.')[0]

        messages.success(request, "文件上传成功并在分类中")
        return render(request, 'classification_app/index.html', {'src_ip': src_ip, 'src_port': src_port,
                                                                 'dst_ip': dst_ip, 'dst_port': dst_port,
                                                                 'protocol': protocol, 'result': classify_result})
    return render(request, 'classification_app/index.html')


def statistics(request):
    # 加入流量分类结果统计，并以图表形式传递给statistic模板，便于前端展示
    return render(request, 'classification_app/statistics.html')


def ids(request):
    # 加入文件上传功能并将文件保存至本地文件夹，同时进行文件预处理工作用于前端流量展示和后端流量分类工作，并将预处理后的文件保存至数据库
    if request.method == 'POST':

        myFile = request.FILES.get("myfile", None)  # 获取上传文件，如果没有，则默认为None
        if not myFile:
            messages.error(request, "文件上传失败")
            return render(request, 'classification_app/ids.html')

        destination = open(os.path.join(UPLOAD_PATH, myFile.name), 'wb+')
        for chunk in myFile.chunks():
            destination.write(chunk)
        destination.close()

        src_ip, src_port, dst_ip, dst_port, protocol = get_traffic_info(myFile.name)
        classify_result = ids_traffic_classify(myFile.name)

        messages.success(request, "文件上传成功并在分类中")
        return render(request, 'classification_app/ids.html', {'src_ip': src_ip, 'src_port': src_port,
                                                               'dst_ip': dst_ip, 'dst_port': dst_port,
                                                               'protocol': protocol, 'result': classify_result})
    return render(request, 'classification_app/ids.html')


