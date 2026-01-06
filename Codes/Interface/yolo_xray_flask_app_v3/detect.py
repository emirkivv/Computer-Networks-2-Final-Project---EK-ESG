import os
import cv2
from ultralytics import RTDETR

model = RTDETR("last.pt")

class_names = ["fracture"]

def run_detection(image_path):
    results = model(image_path)
    result = results[0]

    img = cv2.imread(image_path)

    boxes = result.boxes
    for i in range(len(boxes)):
        x1, y1, x2, y2 = map(int, boxes.xyxy[i])
        confidence = float(boxes.conf[i])
        class_id = int(boxes.cls[i])
        label_text = f"{class_names[class_id]} {confidence:.2f}"

        cv2.rectangle(img, (x1, y1), (x2, y2), (0, 255, 0), 2)

        cv2.putText(
            img,
            label_text,
            (x1, y1 - 10),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.6,
            (0, 255, 0),
            2
        )

    output_path = image_path.replace("uploads", "uploads/detected")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    cv2.imwrite(output_path, img)
    return output_path
