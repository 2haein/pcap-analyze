# pcap-analyze
송수신되는 packet을 capture하여 중요 정보를 출력하는 C/C++ 기반 프로그램을 작성하라.  Ethernet Header의 src mac / dst mac IP Header의 src ip / dst ip TCP Header의 src port / dst port Payload(Data)의 hexadecimal value(최대 10바이트까지만)

## 실행
syntax: pcap-test <interface> 
sample: pcap-test wlan0

## dummy interface 추가
![6](https://user-images.githubusercontent.com/46235778/183053417-2d468fb7-7786-4025-bab5-6ae02529eff7.PNG)

## ifconfig 명령어를 통해 dummy가 올라간 network interface 확인 가능합니다
![7](https://user-images.githubusercontent.com/46235778/183053436-2cacd562-95ed-4443-a784-9755703edb24.PNG)

## tcpreplay 명령어를 이용하여 해당 interface에 패킷을 전송 가능합니다
![5](https://user-images.githubusercontent.com/46235778/183053482-d9fd1bc4-025b-4a82-85e2-24a63c9579ba.PNG)

## 패킷 스니핑 테스트
![4](https://user-images.githubusercontent.com/46235778/183053505-cd1bcd8d-3c45-46bd-9617-f12ff5389229.PNG)

## Interface 사용 후 다음 명령어를 통해 Interface 삭제
![9](https://user-images.githubusercontent.com/46235778/183053550-f9818506-b56a-4169-b334-0bfe20b13fba.PNG)
